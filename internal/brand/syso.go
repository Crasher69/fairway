package brand

import (
	"bytes"
	"encoding/binary"
)

// Windows-ресурс с иконкой в виде объектного файла COFF.
//
// Go-линковщик подхватывает файлы *.syso из каталога main-пакета и
// вшивает секцию .rsrc в PE-файл — так у exe появляется значок в проводнике
// и в заголовке окна. Обычно .syso делают внешними утилитами (rsrc,
// go-winres); здесь он собирается сам, чтобы не тащить зависимость ради
// двух сотен байт заголовков. Формат описан в спецификации PE/COFF:
// заголовок файла, одна секция .rsrc, дерево ресурсов в три уровня
// (тип → идентификатор → язык), записи данных, таблица перемещений и один
// символ секции.

// Machine — архитектура для заголовка COFF и тип перемещения для неё.
type Machine struct {
	Name  string // суффикс имени файла: amd64, arm64, 386
	id    uint16 // IMAGE_FILE_MACHINE_*
	reloc uint16 // IMAGE_REL_*_ADDR32NB: адрес относительно начала образа
}

// Machines — все Windows-цели, под которые собирается fairway.
var Machines = []Machine{
	{"amd64", 0x8664, 3}, // IMAGE_REL_AMD64_ADDR32NB
	{"arm64", 0xaa64, 2}, // IMAGE_REL_ARM64_ADDR32NB
	{"386", 0x014c, 7},   // IMAGE_REL_I386_DIR32NB
}

const (
	rtIcon      = 3
	rtGroupIcon = 14
	langEnglish = 0x0409
	subdirFlag  = 0x80000000
)

// Syso собирает объектный файл с иконкой приложения для заданной машины.
func Syso(m Machine) []byte {
	images := iconImages()

	// --- содержимое ресурсов ---
	blobs := make([][]byte, 0, len(images)+1)
	for _, im := range images {
		blobs = append(blobs, im.data)
	}
	blobs = append(blobs, groupIcon(images))

	// --- раскладка секции .rsrc ---
	// Порядок: корень (2 типа) → каталоги типов → каталоги языков →
	// записи данных → сами данные. Размеры считаем заранее, чтобы
	// проставить смещения.
	const dirSize, entrySize, dataEntrySize = 16, 8, 16
	nIcons := len(images)
	nLeaves := nIcons + 1

	rootOff := 0
	iconDirOff := rootOff + dirSize + 2*entrySize
	groupDirOff := iconDirOff + dirSize + nIcons*entrySize
	langDirsOff := groupDirOff + dirSize + entrySize
	dataEntriesOff := langDirsOff + nLeaves*(dirSize+entrySize)
	dataOff := align(dataEntriesOff+nLeaves*dataEntrySize, 8)

	var sec bytes.Buffer
	le := binary.LittleEndian
	u16 := func(v int) { binary.Write(&sec, le, uint16(v)) }
	u32 := func(v int) { binary.Write(&sec, le, uint32(v)) }
	dir := func(entries int) {
		u32(0)
		u32(0)
		u16(0)
		u16(0)
		u16(0)
		u16(entries)
	}
	entry := func(id, offset int) { u32(id); u32(offset) }

	// Корень: типы по возрастанию идентификатора.
	dir(2)
	entry(rtIcon, subdirFlag|iconDirOff)
	entry(rtGroupIcon, subdirFlag|groupDirOff)

	// Каталог RT_ICON: изображения с идентификаторами 1..N.
	dir(nIcons)
	for i := range images {
		entry(i+1, subdirFlag|(langDirsOff+i*(dirSize+entrySize)))
	}
	// Каталог RT_GROUP_ICON: одна группа с идентификатором 1.
	dir(1)
	entry(1, subdirFlag|(langDirsOff+nIcons*(dirSize+entrySize)))

	// Каталоги языков: по одному на лист, каждый ведёт к записи данных.
	for i := 0; i < nLeaves; i++ {
		dir(1)
		entry(langEnglish, dataEntriesOff+i*dataEntrySize)
	}

	// Записи данных. Первое поле — RVA данных; линковщик прибавит к нему
	// адрес секции по таблице перемещений ниже.
	relocs := make([]int, 0, nLeaves)
	off := dataOff
	for _, blob := range blobs {
		relocs = append(relocs, sec.Len())
		u32(off)
		u32(len(blob))
		u32(0)
		u32(0)
		off = align(off+len(blob), 8)
	}
	pad(&sec, dataOff)
	for _, blob := range blobs {
		sec.Write(blob)
		pad(&sec, align(sec.Len(), 8))
	}
	raw := sec.Bytes()

	// --- объектный файл ---
	const fileHeader, sectionHeader, relocSize, symbolSize = 20, 40, 10, 18
	rawOff := fileHeader + sectionHeader
	relocOff := rawOff + len(raw)
	symOff := relocOff + len(relocs)*relocSize

	var out bytes.Buffer
	w16 := func(v int) { binary.Write(&out, le, uint16(v)) }
	w32 := func(v int) { binary.Write(&out, le, uint32(v)) }

	// IMAGE_FILE_HEADER
	w16(int(m.id))
	w16(1) // секций
	w32(0) // время
	w32(symOff)
	w32(1)      // символов
	w16(0)      // необязательного заголовка нет
	w16(0x0104) // 32BIT_MACHINE | LINE_NUMS_STRIPPED

	// IMAGE_SECTION_HEADER
	out.Write([]byte(".rsrc\x00\x00\x00"))
	w32(0) // VirtualSize
	w32(0) // VirtualAddress
	w32(len(raw))
	w32(rawOff)
	w32(relocOff)
	w32(0) // строк нет
	w16(len(relocs))
	w16(0)
	w32(0x40000040) // INITIALIZED_DATA | MEM_READ

	out.Write(raw)

	// IMAGE_RELOCATION: каждая указывает на символ №0 — саму секцию.
	for _, r := range relocs {
		w32(r)
		w32(0)
		w16(int(m.reloc))
	}

	// IMAGE_SYMBOL секции .rsrc.
	out.Write([]byte(".rsrc\x00\x00\x00"))
	w32(0)           // Value
	w16(1)           // SectionNumber
	w16(0)           // Type
	out.WriteByte(3) // IMAGE_SYM_CLASS_STATIC
	out.WriteByte(0) // NumberOfAuxSymbols

	// Таблица строк: пустая, но её длина обязана присутствовать.
	w32(4)
	return out.Bytes()
}

// groupIcon — содержимое RT_GROUP_ICON: список изображений с их
// идентификаторами. Проводник по нему выбирает размер под контекст.
func groupIcon(images []iconImage) []byte {
	var buf bytes.Buffer
	le := binary.LittleEndian
	binary.Write(&buf, le, uint16(0))
	binary.Write(&buf, le, uint16(1))
	binary.Write(&buf, le, uint16(len(images)))
	for i, im := range images {
		buf.WriteByte(byte(im.size))
		buf.WriteByte(byte(im.size))
		buf.WriteByte(0)
		buf.WriteByte(0)
		binary.Write(&buf, le, uint16(1))
		binary.Write(&buf, le, uint16(32))
		binary.Write(&buf, le, uint32(len(im.data)))
		binary.Write(&buf, le, uint16(i+1))
	}
	return buf.Bytes()
}

func align(n, to int) int { return (n + to - 1) / to * to }

func pad(buf *bytes.Buffer, to int) {
	if buf.Len() < to {
		buf.Write(make([]byte, to-buf.Len()))
	}
}

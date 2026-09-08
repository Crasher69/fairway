// Package brand — иконка Fairway и всё, что нужно, чтобы зашить её в
// бинарник и в панель.
//
// Иконка: флажок на грине — зелёный скруглённый квадрат, белый шест и три
// белые полосы разной длины. Полосы — одновременно флаг (fairway — участок
// поля для гольфа, флажок отмечает лунку) и шкала рейтинга: три уровня,
// которыми балансировщик ранжирует прокси. На 16 пикселях читается как флаг,
// вблизи — как рейтинг.
//
// Растр рисуется здесь же, без библиотек: фигуры простые (скруглённый
// прямоугольник и капсулы), их можно посчитать по расстоянию до отрезка
// и сгладить суперсэмплингом. Тот же рисунок лежит в internal/admin/web/icon.svg
// для панели — геометрия ниже повторяет его один в один, и менять их нужно
// вместе.
package brand

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Геометрия в координатах 64×64 — как в icon.svg.
const canvas = 64.0

// shape — прямоугольник со скруглёнными углами; при radius = половине
// меньшей стороны вырождается в капсулу.
type shape struct{ x, y, w, h, r float64 }

var (
	background = shape{0, 0, 64, 64, 14}
	marks      = []shape{
		{21, 12, 4, 40, 2},      // шест
		{27, 12, 22, 5, 2.5},    // верхняя полоса
		{27, 21, 16, 5, 2.5},    // средняя
		{27, 30, 10, 5, 2.5},    // нижняя
		{14, 50, 18, 4.5, 2.25}, // земля
	}
	// Фон — вертикальный градиент: сверху светлее. Плоский зелёный на
	// больших размерах выглядел бы наклейкой.
	top    = color.RGBA{0x35, 0xa8, 0x73, 0xff}
	bottom = color.RGBA{0x1e, 0x7a, 0x54, 0xff}
	ink    = color.RGBA{0xff, 0xff, 0xff, 0xff}
)

// inside сообщает, лежит ли точка (в координатах 64×64) внутри фигуры.
func (s shape) inside(px, py float64) bool {
	r := math.Min(s.r, math.Min(s.w, s.h)/2)
	// Расстояние до внутреннего прямоугольника (со срезанными на r краями):
	// точка внутри фигуры, если оно не больше r.
	dx := math.Max(math.Max(s.x+r-px, px-(s.x+s.w-r)), 0)
	dy := math.Max(math.Max(s.y+r-py, py-(s.y+s.h-r)), 0)
	return dx*dx+dy*dy <= r*r
}

// Render рисует иконку заданного размера. Сглаживание — суперсэмплинг
// 4×4 на пиксель: для таких размеров это быстрее и проще любой
// аналитической растеризации.
func Render(size int) *image.RGBA {
	const ss = 4
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	scale := canvas / float64(size)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) * scale
					py := (float64(y) + (float64(sy)+0.5)/ss) * scale
					if !background.inside(px, py) {
						continue
					}
					c := gradient(py / canvas)
					for _, m := range marks {
						if m.inside(px, py) {
							c = ink
							break
						}
					}
					r += float64(c.R)
					g += float64(c.G)
					b += float64(c.B)
					a += 255
				}
			}
			n := float64(ss * ss)
			// Цвет усредняем только по покрытым сэмплам, иначе край
			// потемнел бы к прозрачному чёрному.
			if a > 0 {
				covered := a / 255
				img.SetRGBA(x, y, color.RGBA{
					R: uint8(math.Round(r / covered * (a / n) / 255)),
					G: uint8(math.Round(g / covered * (a / n) / 255)),
					B: uint8(math.Round(b / covered * (a / n) / 255)),
					A: uint8(math.Round(a / n)),
				})
			}
		}
	}
	return img
}

func gradient(t float64) color.RGBA {
	mix := func(a, b uint8) uint8 { return uint8(math.Round(float64(a) + (float64(b)-float64(a))*t)) }
	return color.RGBA{mix(top.R, bottom.R), mix(top.G, bottom.G), mix(top.B, bottom.B), 0xff}
}

// PNG кодирует иконку заданного размера.
func PNG(size int) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, Render(size))
	return buf.Bytes()
}

// IconSizes — набор размеров для ICO и ресурса Windows: от значка в
// заголовке окна до плитки в проводнике.
var IconSizes = []int{16, 24, 32, 48, 64, 256}

// iconImage — одно изображение внутри ICO/ресурса.
type iconImage struct {
	size int
	data []byte // DIB или PNG
}

// iconImages готовит изображения для ICO. Мелкие — классическим DIB:
// его понимают все версии Windows и все места, где рисуется значок.
// 256 — PNG: DIB такого размера весил бы четверть мегабайта.
func iconImages() []iconImage {
	out := make([]iconImage, 0, len(IconSizes))
	for _, size := range IconSizes {
		if size >= 256 {
			out = append(out, iconImage{size, PNG(size)})
		} else {
			out = append(out, iconImage{size, dib(Render(size))})
		}
	}
	return out
}

// dib кодирует картинку в формат иконочного DIB: BITMAPINFOHEADER с
// удвоенной высотой, 32-битные BGRA-строки снизу вверх и однобитная маска
// AND следом. Маска нулевая — прозрачность несёт альфа-канал.
func dib(img *image.RGBA) []byte {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	maskStride := ((w + 31) / 32) * 4
	var buf bytes.Buffer
	le := binary.LittleEndian

	hdr := make([]byte, 40)
	le.PutUint32(hdr[0:], 40)
	le.PutUint32(hdr[4:], uint32(w))
	le.PutUint32(hdr[8:], uint32(h*2))
	le.PutUint16(hdr[12:], 1)
	le.PutUint16(hdr[14:], 32)
	le.PutUint32(hdr[20:], uint32(w*h*4+maskStride*h))
	buf.Write(hdr)

	row := make([]byte, w*4)
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.RGBAAt(x, y)
			row[x*4+0] = c.B
			row[x*4+1] = c.G
			row[x*4+2] = c.R
			row[x*4+3] = c.A
		}
		buf.Write(row)
	}
	buf.Write(make([]byte, maskStride*h))
	return buf.Bytes()
}

// ICO собирает многоразмерный файл .ico.
func ICO() []byte {
	images := iconImages()
	var buf bytes.Buffer
	le := binary.LittleEndian

	head := make([]byte, 6)
	le.PutUint16(head[2:], 1)
	le.PutUint16(head[4:], uint16(len(images)))
	buf.Write(head)

	offset := 6 + 16*len(images)
	for _, im := range images {
		entry := make([]byte, 16)
		entry[0] = byte(im.size) // 256 переполняется в 0 — так и задумано форматом
		entry[1] = byte(im.size)
		le.PutUint16(entry[4:], 1)
		le.PutUint16(entry[6:], 32)
		le.PutUint32(entry[8:], uint32(len(im.data)))
		le.PutUint32(entry[12:], uint32(offset))
		buf.Write(entry)
		offset += len(im.data)
	}
	for _, im := range images {
		buf.Write(im.data)
	}
	return buf.Bytes()
}

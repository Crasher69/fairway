package brand

import (
	"bytes"
	"debug/pe"
	"image/png"
	"testing"
)

func TestRenderIsOpaqueInsideAndTransparentInCorners(t *testing.T) {
	img := Render(64)
	if c := img.RGBAAt(0, 0); c.A != 0 {
		t.Errorf("угол скруглённого квадрата должен быть прозрачным, альфа %d", c.A)
	}
	if c := img.RGBAAt(32, 40); c.A != 255 || c.G < c.R {
		t.Errorf("середина должна быть непрозрачной и зелёной: %+v", c)
	}
	// Шест: белый.
	if c := img.RGBAAt(23, 30); c.R < 250 || c.G < 250 || c.B < 250 {
		t.Errorf("на шесте ожидался белый, получен %+v", c)
	}
}

func TestPNGDecodes(t *testing.T) {
	for _, size := range IconSizes {
		img, err := png.Decode(bytes.NewReader(PNG(size)))
		if err != nil {
			t.Fatalf("%d: %v", size, err)
		}
		if img.Bounds().Dx() != size {
			t.Errorf("размер %d, получен %d", size, img.Bounds().Dx())
		}
	}
}

func TestICOHeader(t *testing.T) {
	ico := ICO()
	if ico[2] != 1 || int(ico[4]) != len(IconSizes) {
		t.Errorf("заголовок ICO: тип %d, изображений %d", ico[2], ico[4])
	}
}

// Объектный файл должен разбираться стандартным debug/pe: тем же кодом
// его читает линковщик Go.
func TestSysoIsValidCOFF(t *testing.T) {
	for _, m := range Machines {
		f, err := pe.NewFile(bytes.NewReader(Syso(m)))
		if err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		if f.Machine != m.id {
			t.Errorf("%s: машина %#x", m.Name, f.Machine)
		}
		if len(f.Sections) != 1 || f.Sections[0].Name != ".rsrc" {
			t.Fatalf("%s: секции %v", m.Name, f.Sections)
		}
		sec := f.Sections[0]
		if int(sec.NumberOfRelocations) != len(IconSizes)+1 {
			t.Errorf("%s: перемещений %d, ожидалось %d", m.Name, sec.NumberOfRelocations, len(IconSizes)+1)
		}
		if len(f.Symbols) != 1 || f.Symbols[0].Name != ".rsrc" || f.Symbols[0].SectionNumber != 1 {
			t.Errorf("%s: символы %+v", m.Name, f.Symbols)
		}
		data, err := sec.Data()
		if err != nil {
			t.Fatal(err)
		}
		// Корень дерева: два типа ресурсов (RT_ICON и RT_GROUP_ICON).
		if data[14] != 2 {
			t.Errorf("%s: в корне %d типов ресурсов", m.Name, data[14])
		}
		f.Close()
	}
}

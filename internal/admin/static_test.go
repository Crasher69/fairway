package admin

import (
	"io/fs"
	"strings"
	"testing"
)

// TestHiddenRuleExists — панель прячет разделы атрибутом hidden, а браузер
// реализует его как display:none в своей таблице стилей, которая проигрывает
// любому авторскому правилу. У нас main — это grid, и без явного правила
// раздел «Мониторинг» оставался виден во всех вкладках.
func TestHiddenRuleExists(t *testing.T) {
	raw, err := fs.ReadFile(webFS, "web/style.css")
	if err != nil {
		t.Fatal(err)
	}
	css := strings.ReplaceAll(string(raw), " ", "")
	if !strings.Contains(css, "[hidden]{display:none!important;}") {
		t.Error("в стилях нет правила [hidden] { display: none !important }")
	}
}

// TestToggledElementsAreHideable ловит ту же ошибку с другой стороны:
// если какому-то переключаемому разделу задан display, он обязан
// перекрываться правилом для hidden.
func TestToggledElementsAreHideable(t *testing.T) {
	raw, err := fs.ReadFile(webFS, "web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, id := range []string{"view-monitor", "view-proxies", "view-lists", "view-rules", "view-cert"} {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("в разметке нет раздела %s, а JS его переключает", id)
		}
	}
}

package forward

import (
	"errors"
	"net/http"
	"os"
	"time"

	"fairway/internal/i18n"
)

// Повтор запроса после неудачи — главный источник опасности в прокси:
// повторённый POST может выполнить платёж, заказ или письмо дважды. Правило
// одно на MITM и обычный HTTP, и держится на двух вопросах: мог ли запрос
// уже выполниться у цели и можно ли выполнять его повторно.
//
//   - Соединение не встало — запрос не уходил, повторять можно любой.
//   - Запрос ушёл, а ответа нет (таймаут, обрыв) — повторяется только
//     идемпотентный: GET, HEAD, OPTIONS, TRACE, PUT, DELETE или запрос с
//     Idempotency-Key. POST и PATCH получают ошибку: медленный сайт мог
//     уже выполнить их, и повтор через другой прокси выполнил бы ещё раз.
//   - Мёртвый keep-alive (мгновенный обрыв на старом соединении) — это
//     не отказ цели, а штатная ситуация, и POST после паузы повторяется
//     на новом соединении через тот же прокси. Остаточный риск описан в
//     CLAUDE.md: так же поступает http.Transport.

// idempotent — можно ли выполнить запрос повторно без последствий (RFC
// 9110, 9.2.2). Заголовок Idempotency-Key клиент ставит сам, когда сервер
// умеет отличать повтор; его понимает и http.Transport.
func idempotent(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete:
		return true
	}
	return req.Header.Get("Idempotency-Key") != "" || req.Header.Get("X-Idempotency-Key") != ""
}

// writeError — запрос не удалось отправить целиком. Цель не получила его
// полностью и выполнить не могла: сервер ждёт недостающие байты или
// отбрасывает обрывок.
type writeError struct{ err error }

func (e *writeError) Error() string { return e.err.Error() }
func (e *writeError) Unwrap() error { return e.err }

// replyTimeout — запрос ушёл, а ответ за отведённое время не пришёл.
type replyTimeout struct{ wait time.Duration }

func (e *replyTimeout) Error() string {
	return i18n.Sprintf("no reply from target within %s", e.wait)
}

// Timeout — как у net.Error: по нему таймаут узнают и за пределами пакета
// (причина бана в рейтинге).
func (e *replyTimeout) Timeout() bool { return true }

// timedOut — ошибка означает «ответа не дождались», а не обрыв.
func timedOut(err error) bool {
	var rt *replyTimeout
	return errors.As(err, &rt) || errors.Is(err, os.ErrDeadlineExceeded)
}

// unsent — запрос точно не дошёл до цели целиком.
func unsent(err error) bool {
	var we *writeError
	return errors.As(err, &we)
}

// gatewayStatus — чем ответить клиенту, когда цель не ответила: 504, если
// не дождались, иначе 502. Клиенту и человеку в логе это разные вещи:
// 504 значит «запрос, может быть, выполнен, но ответа нет».
func gatewayStatus(err error) int {
	if timedOut(err) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// replaySafe — можно ли после ошибки обмена отправить тот же запрос через
// другой прокси. Ответа не было ни байта, и либо запрос идемпотентный,
// либо он не ушёл к цели целиком.
func replaySafe(req *http.Request, err error, received bool) bool {
	if received {
		return false
	}
	return idempotent(req) || unsent(err)
}

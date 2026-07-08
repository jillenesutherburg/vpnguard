//go:build windows

// Package ipc implements the named-pipe control channel for the tray UI.
//
// The wire protocol is line-delimited JSON, one request per connection,
// adopted verbatim from the C# VpnSentinel tray so it connects unchanged:
//
//	request:  {"cmd":"status"}\n
//	response: {"ok":true,"data":{...}}\n
//
// Commands: status | enable | disable | reload | ping
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// PipeName matches PipeNames.Service in the C# tray.
const PipeName = `\\.\pipe\VpnSentinelService`

// Only SYSTEM and Administrators may talk to the service (the tray runs
// elevated via the scheduled task, exactly like OpenVPN GUI).
// pipeSDDL: кто может обращаться к управляющему пайпу службы.
//   SY  — SYSTEM (сама служба)
//   BA  — администраторы
//   IU  — интерактивно вошедшие пользователи (Interactive Users)
// IU добавлен намеренно: трей запускается под обычным пользователем БЕЗ
// админ-прав (та же модель, что у OpenVPN GUI — непривилегированный GUI +
// привилегированная служба). Без IU обычный юзер не может подключиться к
// пайпу, и трей "не видит службу".
// GA=полный доступ для SY/BA; для IU даём чтение+запись (GR|GW), чтобы
// можно было слать команды, но не менять DACL самого пайпа.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

type Request struct {
	Cmd string `json:"cmd"`
	Arg string `json:"arg,omitempty"`
}

type Response struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

func Success(data interface{}) Response { return Response{OK: true, Data: data} }
func Fail(msg string) Response          { return Response{OK: false, Error: msg} }

// ServiceStatus mirrors the C# ServiceStatus JSON shape field-for-field.
// Optional extensions (agreed in NOTES-FOR-SERVICE.md): dnsWhenDown and
// per-script state/detail — the tray treats them as optional.
type ServiceStatus struct {
	KillswitchEnabled bool           `json:"killswitchEnabled"`
	VpnConnected      bool           `json:"vpnConnected"`
	AdapterName       string         `json:"adapterName,omitempty"`
	AdapterIP         string         `json:"adapterIp,omitempty"`
	Persistent        bool           `json:"persistent"`
	WhitelistMode     bool           `json:"whitelistMode"`
	DNSWhenDown       string         `json:"dnsWhenDown,omitempty"`
	Scripts           []ScriptStatus `json:"scripts"`
}

type ScriptStatus struct {
	Name     string `json:"name"`
	Running  bool   `json:"running"`
	Restarts int    `json:"restarts"`
	State    string `json:"state,omitempty"`  // человекочитаемое состояние (tunnels.State)
	Detail   string `json:"detail,omitempty"` // например "пауза 20s"
}

type Handler func(Request) Response

// Serve listens on the pipe until ctx is cancelled. One request per
// connection, mirroring the C# server.
func Serve(ctx context.Context, handler Handler) error {
	l, err := winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL,
		MessageMode:        false,
	})
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	log.Printf("IPC: слушаю %s", PipeName)
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("IPC accept: %v", err)
				time.Sleep(500 * time.Millisecond)
				continue
			}
		}
		go serveConn(conn, handler)
	}
}

func serveConn(conn net.Conn, handler Handler) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req Request
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	resp := func() Response {
		if err := json.Unmarshal(line, &req); err != nil {
			return Fail("некорректный запрос: " + err.Error())
		}
		return handler(req)
	}()

	out, err := json.Marshal(resp)
	if err != nil {
		out, _ = json.Marshal(Fail("ошибка сериализации ответа"))
	}
	out = append(out, '\n')
	_, _ = conn.Write(out)
}

package main

import (
	"context"
	"strings"
	"testing"
)

func TestConsoleDrainsLongLines(t *testing.T) {
	commands := make(chan string, 8)
	readConsole(context.Background(), strings.NewReader("hello\r\n"+strings.Repeat("x", 100000)+"\n/users\n/quit"), commands)
	var got []string
	for s := range commands {
		got = append(got, s)
	}
	expected := []string{"hello", "/input-line-too-long", "/users", "/quit"}
	if strings.Join(got, "|") != strings.Join(expected, "|") {
		t.Fatalf("%q", got)
	}
}
func TestConsoleCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	commands := make(chan string)
	readConsole(ctx, strings.NewReader("hello\n"), commands)
	if _, ok := <-commands; ok {
		t.Fatal("expected closed command channel")
	}
}

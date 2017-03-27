// +build !windows,!linux,!darwin,!freebsd

package yaputil

func SetConsoleTitle(name string) {
}

func SetConsoleTextColorRed() error {
	return nil
}

func SetConsoleTextColorYellow() error {
	return nil
}

func SetConsoleTextColorGreen() error {
	return nil
}

func SetConsoleTextColorReset() error {
	return nil
}

package main

import (
	"fmt"
	"strings"
)

// slotName/slotRet/slotArgs expose the JNI schema (jni_schema.go) by slot index.
func slotName(slot int) string {
	if slot >= 0 && slot < len(jniSchema) {
		return jniSchema[slot].Name
	}
	if slot >= 0 && slot < len(jniNames) {
		return jniNames[slot]
	}
	return fmt.Sprintf("slot%d", slot)
}
func slotRet(slot int) string {
	if slot >= 0 && slot < len(jniSchema) {
		return jniSchema[slot].Ret
	}
	return "void"
}
func slotArgs(slot int) []string {
	if slot >= 0 && slot < len(jniSchema) {
		return jniSchema[slot].Args
	}
	return nil
}

func category(name string) string {
	switch {
	case strings.HasPrefix(name, "Call") && strings.Contains(name, "Method"):
		return "call"
	case strings.HasPrefix(name, "NewObject") || name == "AllocObject":
		return "new"
	case (strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "Set")) && strings.HasSuffix(name, "Field"),
		strings.HasSuffix(name, "FieldID"):
		return "field"
	case name == "FindClass" || name == "DefineClass" || name == "GetSuperclass" ||
		name == "IsAssignableFrom" || name == "GetObjectClass" || name == "IsInstanceOf":
		return "class"
	case strings.Contains(name, "String"):
		return "string"
	}
	return "other"
}

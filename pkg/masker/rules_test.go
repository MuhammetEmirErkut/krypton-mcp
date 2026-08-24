package masker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateCreditCard(t *testing.T) {
	// Mathematically verified credit card numbers passing Luhn checksum
	validCards := []string{
		"4532-0150-1234-5671", // Visa
		"4532 0150 1234 5671",
		"4532015012345671",
		"4111-1111-1111-1111", // Standard Visa Test
		"5425-2334-3010-9903", // MasterCard
		"3782-822463-10005",   // Amex
		"6011-0009-9013-9424", // Discover
	}

	for _, card := range validCards {
		assert.True(t, ValidateCreditCard(card), "Card %s should be valid", card)
	}

	// Invalid credit cards (bad checksum, bad length, non-digits)
	invalidCards := []string{
		"4532-0150-1234-5674", // Bad Luhn digit (sum=53)
		"1234-5678",           // Too short
		"0000-0000-0000-0001", // Bad checksum
		"invalid-string-text",
	}

	for _, card := range invalidCards {
		assert.False(t, ValidateCreditCard(card), "Card %s should be invalid", card)
	}
}

func TestValidateSSN(t *testing.T) {
	validSSNs := []string{
		"123-45-6789",
		"456-78-1234",
		"219-09-5432",
	}

	for _, ssn := range validSSNs {
		assert.True(t, ValidateSSN(ssn), "SSN %s should be valid", ssn)
	}

	invalidSSNs := []string{
		"000-45-6789", // Invalid 000 area
		"666-45-6789", // Invalid 666 area
		"950-45-6789", // Invalid 9xx area
		"123-00-6789", // Invalid 00 group
		"123-45-0000", // Invalid 0000 serial
		"000000000",
		"12-345-6789",
	}

	for _, ssn := range invalidSSNs {
		assert.False(t, ValidateSSN(ssn), "SSN %s should be invalid", ssn)
	}
}

func TestValidateJWT(t *testing.T) {
	validJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	assert.True(t, ValidateJWT(validJWT))

	invalidJWT := "invalid.jwt.token"
	assert.False(t, ValidateJWT(invalidJWT))
}

package main

import (
	"testing"

	cfg "github.com/conductorone/baton-cloudflare-zero-trust/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/test"
	"github.com/conductorone/baton-sdk/pkg/ustrings"
)

func TestConfigs(t *testing.T) {
	testCases := []test.TestCaseFromExpression{
		{
			"",
			false,
			"empty configs",
		},
		{
			"--account-id 1",
			false,
			"missing api token",
		},
		{
			"--account-id 1 --api-token 1",
			true,
			"with api token",
		},
	}

	test.ExerciseTestCasesFromExpressions(
		t,
		cfg.Config,
		nil,
		ustrings.ParseFlags,
		testCases,
	)
}

package main

import (
	"testing"

	"github.com/conductorone/baton-sdk/pkg/field"
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
			"missing api key or api token",
		},
		{
			"--account-id --api-token 1",
			true,
			"with api token",
		},
		{
			"--account-id --api-key 1",
			false,
			"with api key but missing email ID",
		},
		{
			"--account-id --api-key 1 --email-id 1",
			true,
			"with api key",
		},
		{
			"--account-id --api-key 1 --api-token 1",
			false,
			"api key and api token",
		},
	}

	test.ExerciseTestCasesFromExpressions(
		t,
		field.NewConfiguration(
			configurationFields,
			fieldRelationships...,
		),
		nil,
		ustrings.ParseFlags,
		testCases,
	)
}

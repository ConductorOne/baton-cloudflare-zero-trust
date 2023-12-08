package connector

import (
	"fmt"
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

func parsePageToken(i string, resourceID *v2.ResourceId) (*pagination.Bag, int, error) {
	b := &pagination.Bag{}
	err := b.Unmarshal(i)
	if err != nil {
		return nil, 0, err
	}

	if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceID.ResourceType,
			ResourceID:     resourceID.Resource,
		})
	}

	page, err := getPageFromPageToken(b.PageToken())
	if err != nil {
		return nil, 0, err
	}

	return b, page, nil
}

func getPageFromPageToken(token string) (int, error) {
	if token == "" {
		return 0, nil
	}

	page, err := strconv.ParseInt(token, 10, 64)
	if err != nil {
		return 0, err
	}

	return int(page), nil
}

func isLastPage(count int, pageSize int) bool {
	return count < pageSize
}

func getPageTokenFromPage(bag *pagination.Bag, page int) (string, error) {
	nextPage := fmt.Sprintf("%d", page)
	pageToken, err := bag.NextToken(nextPage)
	if err != nil {
		return "", err
	}

	return pageToken, nil
}

var resourcePageSize = 50

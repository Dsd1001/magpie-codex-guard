package check

import (
	"errors"
	"strings"
)

func ValidateAccount(account string) error {
	if account == "" || len(account) > 256 || strings.TrimSpace(account) != account {
		return errors.New("账号标识无效")
	}
	for _, r := range account {
		if r < 0x20 || r == 0x7f {
			return errors.New("账号含控制字符")
		}
	}
	return nil
}
func validateAccountModel(model string) error {
	if model == "" || len(model) > 512 || !apiModelPattern.MatchString(model) || strings.HasPrefix(model, "quality-probe/") {
		return errors.New("请选择完整模型 ID")
	}
	for _, r := range model {
		if r < 0x20 || r == 0x7f {
			return errors.New("模型含控制字符")
		}
	}
	return nil
}
func accountTargetID(account, model string) string { return account + "\x1f" + model }

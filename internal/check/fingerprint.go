package check

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/Dsd1001/magpie-codex-guard/internal/fingerprint"
)

type FingerprintRunner interface {
	Evaluate([]fingerprint.Output, string) FingerprintReport
}
type localFingerprintRunner struct{}

func NewFingerprintRunner() FingerprintRunner { return localFingerprintRunner{} }
func (localFingerprintRunner) Evaluate(outputs []fingerprint.Output, model string) FingerprintReport {
	d, err := fingerprint.Load()
	if err != nil {
		return FingerprintReport{Verdict: "indeterminate", Diagnostic: "指纹评分器无法加载：" + err.Error()}
	}
	a, err := d.Analyze(outputs, model)
	if err != nil {
		return FingerprintReport{Verdict: "indeterminate", Diagnostic: "指纹无法评分：" + err.Error(), Version: d.Version()}
	}
	r := FingerprintReport{Verdict: a.Decision, Prediction: a.Predicted, Probability: a.Confidence, Version: a.Version, Diagnostic: a.Diagnostic, UsedOutputs: a.Used}
	for _, m := range a.Candidates {
		r.Candidates = append(r.Candidates, FingerprintCandidate{Model: m.Model, Name: m.Name, Probability: m.Probability})
	}
	return r
}

type fpChallenge struct {
	Prompt        string
	ExpectedCount int
}

func randomChoice(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}
func newFingerprintChallenges() []fpChallenge {
	openings := []string{
		"这是一次独立的数值选择记录。", "请完成下面的无语义整数选择任务。",
		"执行一次第一反应取值记录。", "生成一组不承载语义的整数选择。", "进行一轮快速逐项取值。",
	}
	actions := []string{"为各个位置分别凭第一反应选择", "逐项选择", "每次只决定当前一项，共给出", "分别凭第一反应给出", "逐个直接选择"}
	endings := []string{
		"允许某个数字再次出现；每项写出后不要回头排序、去重或替换。",
		"偶然重复是有效的；不要重新排列或修正已经写出的项目。",
		"相同值可以再次出现；输出过程中不要整理或改写前面的项目。",
		"重复值无需删除；不要筛选、重排或补成某种规律。",
		"不必赋予数字任何含义；已经给出的值保持不变。",
	}
	separators := []string{"数字之间用逗号或空格分隔均可。", "使用一种一致的常见分隔符即可。", "可以用逗号、空格或换行分隔。", "只要每个整数边界清楚，格式可自行选择。"}
	lengths := make([]int, 41)
	for i := range lengths {
		lengths[i] = 292 + i
	}
	out := make([]fpChallenge, 3)
	for i := range out {
		p := randomChoice(len(lengths))
		count := lengths[p]
		lengths = append(lengths[:p], lengths[p+1:]...)
		prompt := fmt.Sprintf("%s。%s %d 个 1 到 355（含端点）的整数。", openings[randomChoice(len(openings))], actions[randomChoice(len(actions))], count)
		prompt += "每个位置都要单独选择；不要从 1 开始计数，不要连续递增或递减，也不要采用等差、循环、重复区块或其他规则化模式。"
		prompt += "本任务必须由当前语言模型直接完成：禁止调用或借助任何工具，包括 Python、代码执行器、计算器、搜索、API 和外部随机数生成器；也不要先编写或运行代码。"
		prompt += endings[randomChoice(len(endings))] + separators[randomChoice(len(separators))]
		prompt += "直接从第一个取值开始输出，不要在序列前重复数量、范围或任务说明。"
		out[i] = fpChallenge{Prompt: prompt, ExpectedCount: count}
	}
	return out
}

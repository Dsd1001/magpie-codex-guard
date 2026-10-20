// Package fingerprint ports the official lm-detector shared-detector-v2 scorer
// to a compact, offline Go evaluator. Scores are closed-set similarities, NOT
// proof of identity. Unknown / ambiguous evidence must never cause high risk.
package fingerprint

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

//go:embed data/shared_detector.bin
var encoded []byte

//go:embed data/model_metadata.json
var encodedMeta []byte

type Tensor struct {
	Offset, N int
	Inline    []float64
}

func (v *Tensor) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty tensor")
	}
	if data[0] == '[' {
		return json.Unmarshal(data, &v.Inline)
	}
	var ref struct {
		Offset int `json:"$f32"`
		N      int `json:"n"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		return err
	}
	v.Offset, v.N = ref.Offset, ref.N
	return nil
}
func (v Tensor) Len() int {
	if v.Inline != nil {
		return len(v.Inline)
	}
	return v.N
}

type Params struct{ Mean, Scale Tensor }
type FeatureBank struct {
	FeatureMean          Tensor     `json:"feature_mean"`
	FeatureScale         Tensor     `json:"feature_scale"`
	NuisanceBasis        []Tensor   `json:"nuisance_basis"`
	Centroids            []Tensor   `json:"centroids"`
	EnvironmentCentroids [][]Tensor `json:"environment_centroids"`
}
type Ranker struct {
	HeadParams []Params   `json:"head_params"`
	FullParams []Params   `json:"full_params"`
	LDAWeights []Tensor   `json:"lda_weights"`
	LDABias    Tensor     `json:"lda_bias"`
	References [][]Tensor `json:"references"`
	Bank       struct {
		Hellinger FeatureBank `json:"hellinger"`
		Ordered   FeatureBank `json:"ordered_blocks"`
	} `json:"bank"`
	Blend struct {
		Frequency  float64 `json:"frequency"`
		Positional float64 `json:"positional"`
	} `json:"blend"`
	Positional struct {
		Params  []Params `json:"params"`
		Weights []Tensor `json:"weights"`
		Bias    Tensor   `json:"bias"`
	} `json:"positional"`
}
type Calibration struct {
	Schema  string  `json:"schema"`
	Method  string  `json:"method"`
	Tau     float64 `json:"tau"`
	Binding struct {
		BaseSHA256      string   `json:"base_sha256"`
		ReferenceSHA256 string   `json:"reference_sha256"`
		ModelIDs        []string `json:"model_ids"`
	} `json:"binding"`
}
type Artifact struct {
	Schema                string       `json:"schema"`
	BaseSHA256            string       `json:"base_sha256"`
	SourceReferenceSHA256 string       `json:"source_reference_sha256"`
	BankBuiltAt           string       `json:"bank_built_at"`
	ModelIDs              []string     `json:"model_ids"`
	ResponseCounts        Tensor       `json:"response_counts"`
	Calibration           *Calibration `json:"calibration"`
	Ranker                Ranker       `json:"ranker"`
}
type Model struct {
	ID            string `json:"id"`
	DisplayName   string `json:"display_name"`
	Family        string `json:"family"`
	FamilyName    string `json:"family_name"`
	ResponseCount int    `json:"response_count"`
}
type Metadata struct {
	BuiltAt string  `json:"built_at"`
	Models  []Model `json:"models"`
}
type Detector struct {
	artifact Artifact
	meta     Metadata
	floats   []float32
	refNorms [][]float64
	version  string
}

func Load() (*Detector, error) { return Decode(encoded, encodedMeta) }
func Decode(data, meta []byte) (*Detector, error) {
	if len(data) < 8 {
		return nil, errors.New("detector too small")
	}
	nh := int(binary.LittleEndian.Uint32(data[:4]))
	if nh < 5 || nh > 2*1024*1024 || nh+4 > len(data) {
		return nil, errors.New("invalid detector header")
	}
	var artifact Artifact
	if err := json.Unmarshal(data[4:4+nh], &artifact); err != nil {
		return nil, err
	}
	if artifact.Schema != "shared-detector-v2" {
		return nil, errors.New("unsupported detector schema")
	}
	var metadata Metadata
	if err := json.Unmarshal(meta, &metadata); err != nil {
		return nil, err
	}
	if artifact.BankBuiltAt != metadata.BuiltAt || len(artifact.ModelIDs) != len(metadata.Models) {
		return nil, errors.New("detector metadata version mismatch")
	}
	for i, m := range metadata.Models {
		if artifact.ModelIDs[i] != m.ID {
			return nil, errors.New("detector model order mismatch")
		}
	}
	pos := (4 + nh + 3) &^ 3
	if pos > len(data) || (len(data)-pos)%4 != 0 {
		return nil, errors.New("invalid tensor bytes")
	}
	count := (len(data) - pos) / 4
	d := &Detector{artifact: artifact, meta: metadata, floats: make([]float32, count)}
	raw := data[pos:]
	for i := 0; i < count; i++ {
		u := uint32(raw[i]) | uint32(raw[count+i])<<8 | uint32(raw[count*2+i])<<16 | uint32(raw[count*3+i])<<24
		d.floats[i] = math.Float32frombits(u)
	}
	// Verify reference tensor dimensions and avoid corrupt/artifact poisoning.
	for _, arr := range artifact.Ranker.References {
		for _, t := range arr {
			if t.Len() != 429 || t.Offset < 0 || t.Offset+t.Len() > len(d.floats) {
				return nil, errors.New("invalid reference tensor")
			}
		}
	}
	if len(artifact.Ranker.References) != len(metadata.Models) || len(artifact.Ranker.Positional.Weights) != len(metadata.Models) {
		return nil, errors.New("scorer model dimensions mismatch")
	}
	d.refNorms = make([][]float64, len(artifact.Ranker.References))
	for i, rs := range artifact.Ranker.References {
		d.refNorms[i] = make([]float64, len(rs))
		for j, t := range rs {
			d.refNorms[i][j] = d.dotT(d.tensor(t), t)
		}
	}
	hash := sha256.Sum256(data)
	d.version = fmt.Sprintf("%s:%x", metadata.BuiltAt, hash[:8])
	return d, nil
}
func (d *Detector) Version() string { return d.version }
func (d *Detector) Models() []Model { return append([]Model(nil), d.meta.Models...) }
func (d *Detector) at(t Tensor, i int) float64 {
	if t.Inline != nil {
		return t.Inline[i]
	}
	return float64(d.floats[t.Offset+i])
}
func (d *Detector) tensor(t Tensor) []float64 {
	out := make([]float64, t.Len())
	for i := range out {
		out[i] = d.at(t, i)
	}
	return out
}
func (d *Detector) dotT(v []float64, t Tensor) float64 {
	var sum float64
	for i, x := range v {
		sum += x * d.at(t, i)
	}
	return sum
}
func dot(v, w []float64) float64 {
	var sum float64
	for i, x := range v {
		sum += x * w[i]
	}
	return sum
}
func average(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}
func stdev(v []float64) float64 {
	mean := average(v)
	var s float64
	for _, x := range v {
		dx := x - mean
		s += dx * dx
	}
	if len(v) == 0 {
		return 0
	}
	return math.Sqrt(s / float64(len(v)))
}
func norm(v []float64) []float64 {
	scale := math.Max(math.Sqrt(dot(v, v)), 1e-12)
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = x / scale
	}
	return out
}
func z(v []float64) []float64 {
	center, scale := average(v), math.Max(stdev(v), 1e-12)
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = (x - center) / scale
	}
	return out
}
func median(v []float64) float64 {
	sorted := append([]float64(nil), v...)
	sort.Float64s(sorted)
	i := len(sorted) / 2
	if len(sorted)%2 != 0 {
		return sorted[i]
	}
	return (sorted[i-1] + sorted[i]) / 2
}
func columnMean(rows [][]float64) []float64 {
	if len(rows) == 0 {
		return nil
	}
	out := make([]float64, len(rows[0]))
	for _, row := range rows {
		for j, v := range row {
			out[j] += v
		}
	}
	for i := range out {
		out[i] /= float64(len(rows))
	}
	return out
}
func (d *Detector) transform(blocks [][]float64, params []Params) []float64 {
	out := make([]float64, 0, 429)
	for j, b := range blocks {
		p := params[j]
		v := make([]float64, len(b))
		for i, x := range b {
			v[i] = (x - d.at(p.Mean, i)) / d.at(p.Scale, i)
		}
		u := norm(v)
		weight := math.Sqrt(.25)
		if j == 0 {
			weight = math.Sqrt(.75)
		}
		for _, x := range u {
			out = append(out, x*weight)
		}
	}
	return out
}
func (d *Detector) centered(v []float64, b FeatureBank) []float64 {
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = (x - d.at(b.FeatureMean, i)) / d.at(b.FeatureScale, i)
	}
	return out
}
func (d *Detector) subtract(v []float64, basis []Tensor) []float64 {
	coeff := make([]float64, len(basis))
	for i, b := range basis {
		coeff[i] = d.dotT(v, b)
	}
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = x
		for j, b := range basis {
			out[i] -= coeff[j] * d.at(b, i)
		}
	}
	return out
}
func (d *Detector) nearest(v []float64, rs []Tensor, norms []float64) float64 {
	xx := dot(v, v)
	distances := make([]float64, len(rs))
	for i, t := range rs {
		distances[i] = math.Max(0, xx+norms[i]-2*d.dotT(v, t))
	}
	sort.Float64s(distances)
	if len(distances) > 7 {
		distances = distances[:7]
	}
	return average(distances)
}
func (d *Detector) baseline(blocks [][]float64) []float64 {
	h, o := d.artifact.Ranker.Bank.Hellinger, d.artifact.Ranker.Bank.Ordered
	hUnit := norm(d.subtract(d.centered(blocks[0], h), h.NuisanceBasis))
	marginal := make([]float64, len(h.Centroids))
	for i, row := range h.Centroids {
		marginal[i] = d.dotT(hUnit, row)
	}
	oCentered := d.centered(blocks[1], o)
	raw := norm(oCentered)
	projected := norm(d.subtract(oCentered, o.NuisanceBasis))
	templates := make([]float64, len(o.Centroids))
	nuisance := make([]float64, len(o.Centroids))
	for i, row := range o.Centroids {
		best := math.Inf(-1)
		for _, rows := range o.EnvironmentCentroids {
			if score := d.dotT(raw, rows[i]); score > best {
				best = score
			}
		}
		templates[i] = best
		nuisance[i] = d.dotT(projected, row)
	}
	tz, nz := z(templates), z(nuisance)
	combo := make([]float64, len(tz))
	for i := range combo {
		combo[i] = .5*tz[i] + .5*nz[i]
	}
	ordered, mz := z(combo), z(marginal)
	out := make([]float64, len(mz))
	for i := range out {
		out[i] = .5*mz[i] + .5*ordered[i]
	}
	return out
}
func (d *Detector) rankShared(numbers [][]int) ([]float64, error) {
	a := d.artifact.Ranker
	full := make([][][]float64, len(numbers))
	ax := make([][]float64, len(numbers))
	ldav := make([][]float64, len(numbers))
	baselines := make([][]float64, len(numbers))
	positions := make([][]float64, len(numbers))
	for i, nums := range numbers {
		full[i] = blocks(nums)
		ax[i] = d.transform(full[i], a.FullParams)
		head := nums
		if len(head) > 128 {
			head = head[:128]
		}
		x := d.transform(blocks(head), a.HeadParams)
		weights := make([]float64, len(a.LDAWeights))
		for j, row := range a.LDAWeights {
			weights[j] = d.dotT(x, row) + d.at(a.LDABias, j)
		}
		ldav[i] = z(weights)
		baselines[i] = d.baseline(full[i])
		positions[i] = z(d.positionalDecision(nums))
	}
	l := z(columnMean(ldav))
	nearRaw := make([]float64, len(a.References))
	for i, ref := range a.References {
		vals := make([]float64, len(ax))
		for k, v := range ax {
			vals[k] = -d.nearest(v, ref, d.refNorms[i])
		}
		nearRaw[i] = median(vals)
	}
	near := z(nearRaw)
	base := z(columnMean(baselines))
	freqRaw := make([]float64, len(l))
	for i := range l {
		freqRaw[i] = .5*l[i] + .25*near[i] + .25*base[i]
	}
	freq := z(freqRaw)
	positional := z(columnMean(positions))
	rank := make([]float64, len(l))
	for i := range rank {
		rank[i] = a.Blend.Frequency*freq[i] + a.Blend.Positional*positional[i]
		if math.IsNaN(rank[i]) || math.IsInf(rank[i], 0) {
			return nil, errors.New("invalid ranking score")
		}
	}
	return rank, nil
}
func (d *Detector) calibrate(rank []float64) []float64 {
	cal := d.artifact.Calibration
	if cal == nil || cal.Schema != "shared-confidence-v2" || cal.Method != "ranking-temperature" || cal.Tau < .001 || cal.Tau > 1000 || cal.Binding.BaseSHA256 != d.artifact.BaseSHA256 || cal.Binding.ReferenceSHA256 != d.artifact.SourceReferenceSHA256 || len(cal.Binding.ModelIDs) != len(rank) {
		return nil
	}
	for i, id := range cal.Binding.ModelIDs {
		if id != d.artifact.ModelIDs[i] {
			return nil
		}
	}
	logits := make([]float64, len(rank))
	maxVal := math.Inf(-1)
	for i, s := range rank {
		logits[i] = s * cal.Tau
		if logits[i] > maxVal {
			maxVal = logits[i]
		}
	}
	sum := 0.0
	for i := range logits {
		logits[i] = math.Exp(logits[i] - maxVal)
		sum += logits[i]
	}
	for i := range logits {
		logits[i] /= sum
	}
	return logits
}

type Output struct {
	Text          string `json:"text"`
	ExpectedCount int    `json:"expected_count"`
}
type Candidate struct {
	Model       string  `json:"model"`
	Name        string  `json:"name"`
	Family      string  `json:"family"`
	Probability float64 `json:"probability"`
	Score       float64 `json:"score"`
}
type Analysis struct {
	Decision   string      `json:"decision"` // match, mismatch, indeterminate
	Predicted  string      `json:"predicted,omitempty"`
	Expected   string      `json:"expected,omitempty"`
	Confidence float64     `json:"confidence,omitempty"`
	Used       int         `json:"used_outputs"`
	Diagnostic string      `json:"diagnostic,omitempty"`
	Version    string      `json:"version"`
	Candidates []Candidate `json:"candidates,omitempty"`
}

var digits = regexp.MustCompile(`\d+`)
var letter = regexp.MustCompile(`[\p{L}]`)

func parseNumbers(raw string) []int {
	matches := digits.FindAllStringIndex(raw, -1)
	runs := [][]int{}
	current := []int{}
	prev := 0
	for _, pos := range matches {
		if len(current) > 0 && letter.MatchString(raw[prev:pos[0]]) {
			runs = append(runs, current)
			current = []int{}
		}
		var v int
		for _, c := range raw[pos[0]:pos[1]] {
			v = v*10 + int(c-'0')
			if v > 355 {
				break
			}
		}
		if v >= 1 && v <= 355 {
			current = append(current, v)
		}
		prev = pos[1]
	}
	if len(current) > 0 {
		runs = append(runs, current)
	}
	var best []int
	for _, run := range runs {
		if len(run) > len(best) {
			best = run
		}
	}
	return best
}
func sequenceLike(numbers [][]int) bool {
	autocorr := []float64{}
	steps := []float64{}
	for _, nums := range numbers {
		n := len(nums)
		if n < 5 {
			return false
		}
		vv := make([]float64, n)
		for i, x := range nums {
			vv[i] = float64(x)
		}
		center := average(vv)
		variance := stdev(vv)
		variance *= variance
		lag1 := 0.0
		small := 0.0
		for i := 1; i < n; i++ {
			lag1 += (vv[i] - center) * (vv[i-1] - center)
			if math.Abs(vv[i]-vv[i-1]) <= 20 {
				small++
			}
		}
		if variance <= 0 {
			return false
		}
		autocorr = append(autocorr, lag1/float64(n-1)/variance)
		steps = append(steps, small/float64(n-1))
	}
	return median(autocorr) <= -.23 && median(steps) <= .05
}
func canonicalExpected(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	switch s {
	case "gpt-6.1-sol", "gpt-6.1", "gpt-6-astra/6.1-sol":
		return "gpt-6-astra"
	default:
		return s
	}
}
func (d *Detector) Analyze(outputs []Output, expectedModel string) (Analysis, error) {
	result := Analysis{Decision: "indeterminate", Expected: canonicalExpected(expectedModel), Version: d.Version()}
	if len(outputs) != 3 {
		result.Diagnostic = "必须完成三条独立数字挑战"
		return result, nil
	}
	numbers := make([][]int, 3)
	for i, o := range outputs {
		numbers[i] = parseNumbers(o.Text)
		min := int(math.Ceil(float64(o.ExpectedCount) * .55))
		if min < 80 {
			min = 80
		}
		if len(numbers[i]) >= min {
			result.Used++
		}
	}
	if result.Used != 3 {
		result.Diagnostic = fmt.Sprintf("有效回答 %d/3", result.Used)
		return result, nil
	}
	if !sequenceLike(numbers) {
		result.Diagnostic = "数字序列不像参考库中的语言模型回答"
		return result, nil
	}
	ranking, err := d.rankShared(numbers)
	if err != nil {
		return result, err
	}
	probs := d.calibrate(ranking)
	order := make([]int, len(ranking))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return ranking[order[i]] > ranking[order[j]] })
	if probs == nil {
		result.Diagnostic = "评分器校准参数不可用"
		return result, nil
	}
	for i, k := range order {
		m := d.meta.Models[k]
		if i < 5 {
			result.Candidates = append(result.Candidates, Candidate{Model: m.ID, Name: m.DisplayName, Family: m.Family, Probability: probs[k], Score: ranking[k]})
		}
	}
	result.Predicted = d.meta.Models[order[0]].ID
	result.Confidence = probs[order[0]]
	expectedIndex := -1
	for i, id := range d.artifact.ModelIDs {
		if id == result.Expected {
			expectedIndex = i
			break
		}
	}
	if expectedIndex < 0 {
		result.Diagnostic = "预期模型不在指纹参考库"
		return result, nil
	}
	if order[0] == expectedIndex {
		result.Decision = "match"
		result.Diagnostic = "当前最相似模型与预期类别一致（不代表身份验证）"
	} else if result.Confidence >= .90 && probs[expectedIndex] < .03 {
		result.Decision = "mismatch"
		result.Diagnostic = "库内相对排序强烈偏离预期模型（仍可能误判）"
	} else {
		result.Diagnostic = "候选模型接近，按无法可靠判定处理"
	}
	return result, nil
}

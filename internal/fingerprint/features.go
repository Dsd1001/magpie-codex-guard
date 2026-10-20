package fingerprint

import "math"

func counts(nums []int) []float64 {
	out := make([]float64, 355)
	for _, n := range nums {
		if n >= 1 && n <= 355 {
			out[n-1]++
		}
	}
	return out
}
func hellinger(count []float64) []float64 {
	total := average(count)*float64(len(count)) + .5*355
	out := make([]float64, len(count))
	for i, v := range count {
		out[i] = math.Sqrt((v + .5) / total)
	}
	return out
}
func orderedBlock(nums []int) []float64 {
	out := make([]float64, 0, 74)
	n := len(nums)
	base, extra := n/4, n%4
	start := 0
	for j := 0; j < 4; j++ {
		size := base
		if j < extra {
			size++
		}
		bins := make([]float64, 16)
		for i := range bins {
			bins[i] = .5
		}
		for _, x := range nums[start : start+size] {
			k := int(math.Floor(float64(x-1) / 355 * 16))
			if k > 15 {
				k = 15
			}
			bins[k]++
		}
		start += size
		total := average(bins) * 16
		for _, v := range bins {
			out = append(out, math.Sqrt(v/total))
		}
	}
	last := make([]float64, 10)
	for i := range last {
		last[i] = .5
	}
	for _, x := range nums {
		last[x%10]++
	}
	total := average(last) * 10
	for _, v := range last {
		out = append(out, math.Sqrt(v/total))
	}
	return out
}
func blocks(nums []int) [][]float64 { return [][]float64{hellinger(counts(nums)), orderedBlock(nums)} }

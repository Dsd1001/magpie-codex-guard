package fingerprint

import "math"

var weights = [4]float64{.6, .15, .125, .125}
var lags = []int{1, 2, 3, 5, 8, 13, 21, 34}

func positionKernel(nums []int) []float64 {
	n := len(nums)
	out := make([]float64, 34*3)
	for pos, x := range nums {
		t := (float64(pos)+.5)*2/float64(n) - 1
		basis := [3]float64{t, .5 * (3*t*t - 1), .5 * (5*t*t*t - 3*t)}
		for k := 0; k < 34; k++ {
			weight := 0.0
			if k < 24 {
				centre := 1 + float64(k)*354/23
				diff := (float64(x) - centre) / 20
				weight = math.Exp(-.5 * diff * diff)
			} else if k-24 == x%10 {
				weight = 1
			}
			for j, b := range basis {
				out[k*3+j] += weight * b / float64(n)
			}
		}
	}
	return out
}
func centredTransitions(symbols []int, bins int) []float64 {
	joint := make([]float64, bins*bins)
	for i := range joint {
		joint[i] = .5
	}
	total := float64(len(symbols)-1) + .5*float64(bins*bins)
	for i := 1; i < len(symbols); i++ {
		joint[symbols[i-1]*bins+symbols[i]]++
	}
	rows, cols := make([]float64, bins), make([]float64, bins)
	for i, v := range joint {
		joint[i] = v / total
		rows[i/bins] += joint[i]
		cols[i%bins] += joint[i]
	}
	for i, v := range joint {
		joint[i] = v - rows[i/bins]*cols[i%bins]
	}
	return joint
}
func sequenceFeatures(nums []int) []float64 {
	n := len(nums)
	raw := make([]float64, n)
	for i, x := range nums {
		raw[i] = float64(x)
	}
	m := average(raw)
	sd := math.Max(stdev(raw), 1)
	s := make([]float64, n)
	for i, x := range raw {
		s[i] = (x - m) / sd
	}
	out := make([]float64, 0, 230)
	for _, lag := range lags {
		count := n - lag
		auto, diffAbs, positive, equal, close5, close20 := 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
		for i := 0; i < count; i++ {
			dx := float64(nums[i+lag] - nums[i])
			auto += s[i+lag] * s[i]
			diffAbs += math.Abs(dx)
			if dx > 0 {
				positive++
			}
			if dx == 0 {
				equal++
			}
			if math.Abs(dx) <= 5 {
				close5++
			}
			if math.Abs(dx) <= 20 {
				close20++
			}
		}
		denom := float64(count)
		out = append(out, auto/denom, diffAbs/denom/355, positive/denom, equal/denom, close5/denom, close20/denom)
	}
	sym8, sym10 := make([]int, n), make([]int, n)
	for i, x := range nums {
		sym8[i] = int(math.Min(7, math.Floor(float64(x-1)*8/355)))
		sym10[i] = x % 10
	}
	out = append(out, centredTransitions(sym8, 8)...)
	out = append(out, centredTransitions(sym10, 10)...)
	sameSign, sameDiff, sameLast, zStep1, zStep2 := 0.0, 0.0, 0.0, 0.0, 0.0
	for i := 0; i < n-1; i++ {
		if nums[i]%10 == nums[i+1]%10 {
			sameLast++
		}
		st := math.Abs(s[i+1] - s[i])
		if st > 1 {
			zStep1++
		}
		if st > 2 {
			zStep2++
		}
	}
	for i := 0; i < n-2; i++ {
		a, b := nums[i+1]-nums[i], nums[i+2]-nums[i+1]
		sign := func(x int) int {
			if x > 0 {
				return 1
			}
			if x < 0 {
				return -1
			}
			return 0
		}
		if sign(a) == sign(b) {
			sameSign++
		}
		if a == b {
			sameDiff++
		}
	}
	out = append(out, sameSign/float64(n-2), sameDiff/float64(n-2), sameLast/float64(n-1), zStep1/float64(n-1), zStep2/float64(n-1))
	buckets := make([]int, n)
	for i, x := range nums {
		buckets[i] = int(math.Min(15, math.Floor(float64(x-1)*16/355)))
	}
	for _, width := range []int{4, 8, 16} {
		score := 0.0
		for i := 0; i+width <= n; i++ {
			unique := map[int]bool{}
			for _, k := range buckets[i : i+width] {
				unique[k] = true
			}
			score += float64(len(unique)) / float64(width)
		}
		out = append(out, score/float64(n-width+1))
	}
	return out
}
func (d *Detector) positionalDecision(nums []int) []float64 {
	p := d.artifact.Ranker.Positional
	parts := [][]float64{hellinger(counts(nums)), orderedBlock(nums), positionKernel(nums), sequenceFeatures(nums)}
	var x []float64
	for j, part := range parts {
		param := p.Params[j]
		scaled := make([]float64, len(part))
		for i, v := range part {
			scaled[i] = (v - d.at(param.Mean, i)) / d.at(param.Scale, i)
		}
		unit := norm(scaled)
		for _, v := range unit {
			x = append(x, v*math.Sqrt(weights[j]))
		}
	}
	out := make([]float64, len(p.Weights))
	for i, row := range p.Weights {
		out[i] = d.dotT(x, row) + d.at(p.Bias, i)
	}
	return out
}

package testshard

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func names(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("TestCase%02d", n-i)) // unsorted on purpose
	}
	return out
}

func TestShardsPartitionTheList(t *testing.T) {
	all := names(17)
	for n := 1; n <= 5; n++ {
		seen := map[string]int{}
		for i := 1; i <= n; i++ {
			part, err := Partition(all, i, n)
			if err != nil {
				t.Fatalf("%d/%d: %v", i, n, err)
			}
			for _, name := range part {
				seen[name]++
			}
		}
		if len(seen) != len(all) {
			t.Errorf("n=%d: the shards hold %d names, want %d", n, len(seen), len(all))
		}
		for name, c := range seen {
			if c != 1 {
				t.Errorf("n=%d: %s is in %d shards", n, name, c)
			}
		}
	}
}

func TestPartitionSortsAndStrides(t *testing.T) {
	got, err := Partition([]string{"C", "A", "D", "B", "E"}, 2, 2)
	if err != nil || strings.Join(got, ",") != "B,D" {
		t.Fatalf("got %v, %v; want B,D", got, err)
	}
}

func TestABadShardIsRefused(t *testing.T) {
	for _, bad := range []string{"0/2", "3/2", "x", "1/0", "1", "1/x", "-1/2", ""} {
		if _, _, err := ParseShard(bad); err == nil {
			t.Errorf("ParseShard(%q) was accepted", bad)
		}
	}
	if i, n, err := ParseShard("2/3"); err != nil || i != 2 || n != 3 {
		t.Errorf("ParseShard(2/3) = %d %d %v", i, n, err)
	}
	for _, c := range [][2]int{{0, 2}, {3, 2}, {1, 0}} {
		if _, err := Partition(names(4), c[0], c[1]); err == nil {
			t.Errorf("Partition %d/%d was accepted", c[0], c[1])
		}
	}
}

func TestTheRegexIsAnchored(t *testing.T) {
	re, err := Regex([]string{"TestA", "TestAB"})
	if err != nil || re != "^(TestA|TestAB)$" {
		t.Fatalf("got %q, %v", re, err)
	}
	r := regexp.MustCompile(re)
	if r.MatchString("TestABC") || r.MatchString("XTestA") || !r.MatchString("TestAB") {
		t.Error("the regex is not anchored")
	}
}

func TestAnEmptyShardIsAnError(t *testing.T) {
	if _, err := Regex(nil); err == nil {
		t.Error("an empty list gave a regex")
	}
	if _, err := ShardRegex([]string{"TestA", "TestB"}, 3, 3); err == nil || !strings.Contains(err.Error(), "shard 3/3 is empty") {
		t.Errorf("a shard with no tests: %v", err)
	}
}

func TestCheckFindsAMissingName(t *testing.T) {
	all := names(10)
	if err := Check(all, 3); err != nil {
		t.Fatalf("a good partition: %v", err)
	}
	shards := [][]string{{"A", "C"}, {"B"}}
	if err := covers([]string{"A", "B", "C", "D"}, shards); err == nil || !strings.Contains(err.Error(), "D") {
		t.Errorf("a name in no shard: %v", err)
	}
	dup := [][]string{{"A", "B"}, {"B", "C"}}
	if err := covers([]string{"A", "B", "C"}, dup); err == nil || !strings.Contains(err.Error(), "B") {
		t.Errorf("a name in two shards: %v", err)
	}
	if err := covers([]string{"A"}, [][]string{{"A", "Z"}}); err == nil || !strings.Contains(err.Error(), "Z") {
		t.Errorf("a name that is not a test: %v", err)
	}
}

func TestTheListKeepsTestsFuzzAndExamples(t *testing.T) {
	out := "TestA\nBenchmarkB\nFuzzC\nExampleD\nok  \tpkg\t0.01s\nTestE_sub\n"
	got := ParseList(out)
	want := []string{"ExampleD", "FuzzC", "TestA", "TestE_sub"}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

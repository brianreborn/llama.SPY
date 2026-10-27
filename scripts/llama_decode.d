#!/usr/sbin/dtrace -s
/*
 * llama.SPY — FreeBSD DTrace primary path (v1).
 *
 * Measures llama_decode entry→return latency aggregates for a live process.
 * C++ mangling varies by toolchain; wildcards cover common symbols.
 *
 * Usage (as root / with dtrace privilege):
 *   dtrace -p <PID> -s scripts/llama_decode.d
 *   dtrace -n 'pid$target::*llama_decode*:entry { self->t = timestamp; }
 *              pid$target::*llama_decode*:return /self->t/ {
 *                @ns = avg(timestamp - self->t); self->t = 0; }' -p <PID>
 *
 * One-liner equivalent:
 *   dtrace -p $PID -n '
 *     pid$target::*llama_decode*:entry { self->t = timestamp; }
 *     pid$target::*llama_decode*:return /self->t/ {
 *       @lat_ns = avg(timestamp - self->t);
 *       @count = count();
 *       self->t = 0;
 *     }'
 *
 * Notes:
 *   - Prefer unmangled C API symbols if llama.cpp was built with extern "C"
 *     visibility for llama_decode; otherwise match *llama_decode*.
 *   - macOS can share this script with SIP caveats; Linux uses eBPF later.
 *   - llama.SPY's provider_dtrace_freebsd.cpp may spawn this script and parse
 *     aggregations, or embed libdtrace on FreeBSD builds.
 */

#pragma D option quiet
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
	printf("# llama.SPY DTrace: attaching pid provider for *llama_decode*\n");
	printf("# columns: timestamp_ns decode_count avg_latency_ns\n");
	start = timestamp;
	n = 0;
	sum_ns = 0;
}

pid$target::*llama_decode*:entry
{
	self->t = timestamp;
}

pid$target::*llama_decode*:return
/self->t/
{
	this->dt = timestamp - self->t;
	n++;
	sum_ns += this->dt;
	@avg_ns = avg(this->dt);
	@max_ns = max(this->dt);
	@cnt = count();
	self->t = 0;
}

/* Emit a summary line every second for llama.SPY to scrape from stdout. */
profile:::tick-1s
/n > 0/
{
	printf("%d %d %d\n", timestamp, n, sum_ns / n);
	/* Reset window counters; keep @ aggregations for dtrace end dump. */
	n = 0;
	sum_ns = 0;
}

dtrace:::END
{
	printf("# final aggregations\n");
	printa("avg_ns %@d\n", @avg_ns);
	printa("max_ns %@d\n", @max_ns);
	printa("count %@d\n", @cnt);
}

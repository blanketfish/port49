---
title: Failure matrix
description: What a device login does when each part of port49 is down.
---

# Failure matrix

For each part of port49 that can fail, this matrix gives what the device does, what you see, what to do
and the test or lab note that shows it. Start with "At 3am", the table of the failures that cost a
login. If you begin from a report, an alert or a log line instead, use the
[3am index](index.md); it links here for the device behaviour.

What a device does with an `ERROR` differs by platform. Some fall to their local method at once; some
treat the `ERROR` as final and refuse break-glass until port49d closes its listener. The rows say which,
and a platform a row does not name is unmeasured, not safe.

A row names its evidence. A row that cites a lab note is the measured behaviour. A row that says a case
is open or unmeasured is that, and the behaviour there is unknown.

--8<-- "deploy/failure-matrix.md:3"

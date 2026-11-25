#!/bin/sh
set -eu

cat <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>radperf(1) Manual | radperf-rs</title>
  <meta name="description" content="Read the radperf manual for RADIUS load testing commands, CLI options, input files, accounting, and output formats.">
  <meta name="theme-color" content="#101714">
  <link rel="canonical" href="https://miniradius.github.io/radperf-rs/manual.html">
  <link rel="icon" type="image/png" sizes="32x32" href="favicon.png">
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header class="wrap top"><a class="brand" href="./">← radperf-rs</a></header>
  <main class="wrap manual">
    <h1>radperf(1) Manual</h1>
HTML

manual=$(mandoc -T html -O fragment radperf.1)
printf '%s\n' "$manual" | sed 's/<h1 class="Sh"/<h2 class="Sh"/g; s|</h1>|</h2>|g'

cat <<'HTML'
  </main>
</body>
</html>
HTML

# Stateless scanner integration

This guide describes how a Git scanner should select dependency files and send
their contents to the Comper OSV-Scanner HTTP server. The caller keeps ownership
of repository access; the OSV-Scanner server receives only dependency metadata.

## Endpoint

Send one JSON request per repository revision (or per smaller project shard):

```http
POST /scan HTTP/1.1
Content-Type: application/json
```

```json
{
  "files": [
    {
      "path": "package.json",
      "content": "{\"name\":\"example\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"4.17.20\"}}"
    },
    {
      "path": "package-lock.json",
      "content": "{...}"
    },
    {
      "path": "services/api/requirements-prod.txt",
      "content": "django==5.1.1\n"
    }
  ],
  "date": "2026-08-26"
}
```

`date` is optional. It accepts `YYYY-MM-DD`, RFC 3339, or a UTC date-time
without a suffix. When present, the response excludes vulnerabilities published
after that time.

Do not send `repo` or `commit` with `files`; the two request modes are mutually
exclusive. File content is a normal JSON string, not base64.

## File selection

Match against the repository-relative path using `/` as the separator. Matching
is case-sensitive except for the SBOM rules explicitly marked otherwise.

### Recommended source dependency files

| Ecosystem | Match rule | Notes |
| --- | --- | --- |
| JavaScript/npm | basename `package.json` | Manifest fallback. Send with the lockfile when one exists. See [package.json behavior](#packagejson-behavior). |
| JavaScript/npm | basename `package-lock.json` or `npm-shrinkwrap.json` | Ignore any path containing a `node_modules` segment. |
| JavaScript/pnpm | basename `pnpm-lock.yaml` | Ignore any path containing a `node_modules` segment. |
| JavaScript/Yarn | basename `yarn.lock` | Ignore any path containing a `node_modules` segment. |
| JavaScript/Bun | basename `bun.lock` | `bun.lockb` is not supported by this server version. Ignore `node_modules`. |
| Go | basename `go.mod` | `go.sum` is not an extraction input. |
| Maven | basename `pom.xml`, or any filename ending in `.pom` | Network-backed transitive resolution may be used unless disabled on the server. |
| Gradle | basename `gradle.lockfile` or `buildscript-gradle.lockfile` | Preserve its project-relative path. |
| Gradle | path ending in `/gradle/verification-metadata.xml` | The immediate parent directory must be named `gradle`. |
| Python/pip | basename contains lowercase `requirements` and ends in `.txt` | Examples: `requirements.txt`, `requirements-dev.txt`. `requirements.in` is not supported. |
| Python/Pipenv | basename `Pipfile.lock` | Case-sensitive. |
| Python/PDM | basename `pdm.lock` |  |
| Python/Poetry | basename `poetry.lock` |  |
| Python/PEP 751 | basename `pylock.toml` or matching `pylock.*.toml` |  |
| Python/uv | basename `uv.lock` |  |
| PHP/Composer | basename `composer.lock` |  |
| Ruby/Bundler | basename `Gemfile.lock` or `gems.locked` |  |
| Rust/Cargo | basename `Cargo.lock` | Case-sensitive. |
| Dart/Flutter | basename `pubspec.lock` |  |
| Elixir/Erlang | basename `mix.lock` |  |
| C/C++ Conan | basename `conan.lock` |  |
| R | basename `renv.lock` | Only CRAN entries are currently extracted. |
| Swift | basename `Package.resolved` | Case-sensitive. |
| .NET project | filename ending in `.csproj`, `.vbproj`, or `.fsproj` | Case-sensitive suffix match. |
| .NET dependency context | filename ending in `.deps.json` |  |
| NuGet central package management | basename `Directory.Packages.props` or `Directory.Build.props` |  |
| NuGet packages config | basename `packages.config` |  |
| NuGet lockfile | basename `packages.lock.json` |  |
| Haskell/Cabal | basename `cabal.project.freeze` |  |
| Haskell/Stack | basename `stack.yaml.lock` |  |
| Perl/CPAN installation metadata | basename `META.json` or `META.yml`, with a path containing `/.cpan` | This targets CPAN/CPANM installation metadata, not a normal project manifest. |
| OSV-Scanner JSON | basename `osv-scanner-custom.json` | Accepts OSV-Scanner vulnerability-result JSON as package input. |

Equivalent regular-expression rules for the common project files are:

```text
(^|/)package\.json$
(^|/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock)$
(^|/)go\.mod$
(^|/)(pom\.xml|[^/]+\.pom)$
(^|/)(gradle\.lockfile|buildscript-gradle\.lockfile)$
(^|/)gradle/verification-metadata\.xml$
(^|/)[^/]*requirements[^/]*\.txt$
(^|/)(Pipfile\.lock|pdm\.lock|poetry\.lock|pylock\.toml|pylock\.[^/]+\.toml|uv\.lock)$
(^|/)composer\.lock$
(^|/)(Gemfile\.lock|gems\.locked)$
(^|/)Cargo\.lock$
(^|/)pubspec\.lock$
(^|/)mix\.lock$
(^|/)conan\.lock$
(^|/)renv\.lock$
(^|/)Package\.resolved$
[^/]+\.(csproj|vbproj|fsproj)$
[^/]+\.deps\.json$
(^|/)(Directory\.Packages\.props|Directory\.Build\.props|packages\.config|packages\.lock\.json)$
(^|/)(cabal\.project\.freeze|stack\.yaml\.lock)$
(^|/)osv-scanner-custom\.json$
```

Apply the `node_modules` exclusion separately to the JavaScript lockfile rule.

### SBOM files

The endpoint also accepts these SBOM names:

- CycloneDX, case-insensitive: filenames ending in `.cdx.json` or `.cdx.xml`,
  plus exact basenames `bom.json` and `bom.xml`.
- SPDX, case-insensitive: a basename ending in `.spdx` or containing `.spdx.`,
  with a final supported extension of `.spdx`, `.json`, `.yml`, `.rdf`, or
  `.xml`. Examples include `project.spdx`, `project.spdx.json`, and
  `.spdx.project.xml`. `.yaml` is not supported by this extractor.

The stateless source endpoint is intended for text dependency files and SBOMs.
Do not upload compiled artifacts, container layers, `node_modules`, vendored
source trees, or installed operating-system package databases through this API.

## Preserve file paths and companions

Always send the original repository-relative path, not only the basename. This:

- keeps results attributable to the correct subproject;
- prevents collisions in monorepos;
- preserves relationships between sibling manifest and lock files; and
- lets path-sensitive extractors recognize files such as Gradle verification
  metadata.

Send related files in the same request. In particular:

- send `package.json` next to `package-lock.json` or `npm-shrinkwrap.json`;
- keep every workspace's files under its original directory;
- send parent and child Maven POMs together when they are available; and
- send NuGet project and central package-management files together.

Paths must be relative. Absolute paths, parent traversal (`../`), empty paths,
Windows volume paths, and duplicate normalized paths are rejected.

## `package.json` behavior

When no JavaScript lockfile is available, this Comper build enables SCALIBR's
`package.json` dependency mode. It scans direct entries in `dependencies` by
converting each semver range to its minimum satisfying version. For example,
`^4.17.20` is queried as `4.17.20`.

This is an approximation, not package-manager resolution:

- it does not run npm, Yarn, pnpm, or Bun;
- it does not query a registry to choose the actually installed version;
- it does not reproduce authentication, overrides, resolutions, peer handling,
  platform selection, or package-manager-specific behavior;
- it currently reads `dependencies`, not `devDependencies`,
  `optionalDependencies`, or `peerDependencies`; and
- the root `package.json` must contain both `name` and `version` for the current
  SCALIBR extractor to emit its packages.

Therefore, prefer and send a supported lockfile whenever one is committed. Use
`package.json` alone as a best-effort fallback.

## Request sizing and batching

The server enforces:

- at most 1,000 files per request; and
- at most 32 MiB for the complete JSON request body.

Normally, batch all matches from one repository revision into one request. If a
large monorepo exceeds a limit, shard it by project root while keeping companion
files together. Do not split a manifest from its lockfile merely to parallelize
requests.

The server stages files in a private temporary directory for the duration of the
request and removes that directory afterward. Response source paths are rewritten
back to the supplied repository-relative paths.

## Example request

This example sends local npm files without manually escaping their contents:

```bash
jq -n \
  --rawfile package package.json \
  --rawfile lock package-lock.json \
  '{files: [
    {path: "package.json", content: $package},
    {path: "package-lock.json", content: $lock}
  ]}' | curl --fail-with-body \
    --header 'Content-Type: application/json' \
    --data-binary @- \
    https://scanner.example.com/scan
```

A client that already has file contents in memory should serialize the same
shape directly:

```typescript
type ScanFile = { path: string; content: string };

async function scanDependencyFiles(
  endpoint: string,
  files: ScanFile[],
  date?: string,
) {
  const response = await fetch(`${endpoint}/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ files, ...(date ? { date } : {}) }),
  });

  const body = await response.text();
  if (!response.ok) {
    throw new Error(`OSV scan failed (${response.status}): ${body}`);
  }
  return JSON.parse(body);
}
```

## Response and errors

A successful scan returns HTTP 200, including when vulnerabilities are found.
The JSON response contains:

- `summary`: counts for critical, high, medium, low, unknown, and unmaintained;
- `results`: packages and vulnerabilities grouped by supplied source path; and
- the remaining standard OSV-Scanner vulnerability-result fields.

Treat non-2xx responses as failed scans:

- `400 Bad Request`: malformed JSON, invalid date, invalid paths, duplicate
  paths, conflicting request modes, or request limits;
- `405 Method Not Allowed`: anything other than `POST`; and
- `500 Internal Server Error`: extraction, vulnerability lookup, or other scan
  failure.

Log the HTTP status and response text, but do not log dependency-file contents
unless the repository's data-handling policy permits it.

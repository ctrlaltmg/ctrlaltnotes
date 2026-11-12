---
title: Editing these docs
description: Every page is a plain Markdown file; edit it and rebuild the site with one command.
order: 17
---
# Editing these docs

The documentation is split across the two repositories, and the website build combines them:

```text
ctrlaltnotes-app/                 (repo: ctrlaltnotes)
  docs/technical/                 this technical reference
ctrlaltnotes-website/             (repo: ctrlaltnotes-website)
  docs-src/
    config.json                   site name, URLs, sections, edit links
    guide/                        the user guide
    build.py                      builds site/docs/ from guide/ + ../ctrlaltnotes-app/docs/technical/
```

Technical pages change in the same commit as the code they describe. The website build looks for the application repo next to the website folder (`../ctrlaltnotes-app`); set `CTRLALTNOTES_APP_DIR` to use another checkout, for example in CI.

## Edit

Open any `.md` file in any editor. The top of each file has a small header:

```markdown
---
title: Page title (sidebar + tab)
description: One sentence for search engines and the search box
order: 3
---
```

`order` sorts the sidebar. The file name before the first dash is only for your own sorting.

## Rebuild

```bash
pip install markdown pygments      # once
cd ctrlaltnotes-website
python3 docs-src/build.py          # writes site/docs/ (reads ../ctrlaltnotes-app/docs/technical/)
```

Open `site/docs/index.html` in your browser (or host the `site/` folder anywhere static: GitHub Pages, Netlify, S3).

## Writing features

| Feature | Syntax |
|---|---|
| Callouts | `!!! note "Title"` then an indented body. Kinds: `note`, `tip`, `warning`, `danger` |
| Tables | pipe tables |
| Code | fenced blocks with a language (`bash`, `rust`, `json`, …) |
| Definition lists | `term` newline `:   definition` |
| Links between pages | relative `.md` links, for example `[Sync](06-sync.md)` or `[Security](../technical/13-security-model.md)`. Cross-section links are resolved by section name (`guide`, `technical`), so they work although the two sections live in different repositories |

The builder rewrites `.md` links to `.html` and checks that every link target exists; it fails with a list of broken links.

## Search

The builder creates `search-index.json`. Press `/` or `Ctrl`/`Cmd` + `K` on any page to search.

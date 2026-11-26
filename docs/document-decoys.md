# Document decoys (Word)

A document decoy is a Word file with a tempting name ("Server inventory.docx", "VPN access -
contractors.docx") that reports being opened. Leave it where only an intruder would read it: a file
share, a home folder, a backup archive, a mailbox.

## How it works

The document contains one picture, 1×1 pixel and transparent. The picture is **linked, not
embedded**: in the file it is a relationship of type *image* with `TargetMode="External"` pointing
at the decoy's pixel URL, `https://<ingest>/px/<value>.gif`. To display the page, Word fetches the
picture, and the request is recorded on the ordinary pixel route as a `DOCUMENT` event, severity
HIGH, with Word's user agent (`Mozilla/4.0 (compatible; ms-office; MSOffice 16)`) and the opener's
address (or their proxy's).

Nothing in the file runs code: no macros, no fields to update, no external template. The file is
built on download from the decoy's metadata (`backend/app/services/documents.py`), so the same
decoy always gives the same bytes.

## Setting it up

* `PUBLIC_INGEST_BASE_URL` must be set: the document needs an absolute URL that reaches HoneyShield
  from wherever it will be opened. Without it the type shows as "not set up" and generation is
  refused.
* Console: *Projects & decoys → Word document → Generate*, then *Artifact → Download as: Word
  document*. API: generate with `{"token_type": "DOCUMENT", "generator_params": {"template":
  "server_inventory"}}` (templates: `vpn_access`, `server_inventory`, `salary_review`,
  `board_minutes`; omitted = random), then `GET /api/v1/honey-tokens/{decoy_id}/files/docx`.
* Rename the file if you like; the name is not part of the detection.

## What is not detected

* **Protected View.** Word opens files marked as coming from the internet (email attachments,
  browser downloads) in Protected View and does not load linked pictures until the reader clicks
  *Enable Editing*. Copy the file into place rather than mailing or downloading it there.
* **Viewers that do not fetch linked pictures**: text-only previews, some web viewers, `strings`.
* **No route to the ingest host** from the machine where it is opened.
* **Organisations that block external content** in Office by policy.

Copying the file is not detected; only opening it is.

## Verified

* Microsoft Word 16.115.1 for Mac (macOS 27), 2026-11-23: opening a locally saved decoy fetched the
  picture within seconds, with the user agent above. The test pointed at a local HTTP logger
  rather than a deployed ingest host.
* Not tested: Word for Windows, Word on the web, LibreOffice, Google Docs and Apple Pages.

/* Inbox tab. All dynamic text is inserted with textContent (never innerHTML). */
(() => {
  const { el, $, fmtSize } = window.ShieldUI;

  const VERDICT = {
    genuine: ["Genuine", "Low"],
    unverified: ["Unverified", "Medium"],
    suspicious: ["Suspicious", "Medium"],
    fake: ["Fake / malicious", "High"],
    skipped: ["Skipped", "Low"]
  };

  const AUTH = {
    verified: "Sender verified (SPF/DKIM/DMARC)",
    partial: "Sender partly verified",
    failed: "Sender authentication FAILED",
    unknown: "No sender authentication data"
  };


  // ------------------------------------------------------------
  // Convert the email's Date header into a readable local date/time.
  // Example:
  // "16 Nov 2026, 10:35"
  // ------------------------------------------------------------
  function formatDate(value) {
    if (!value) {
      return "Date unavailable";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return value;
    }

    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(date);
  }


  // ------------------------------------------------------------
  // Load available email providers.
  // ------------------------------------------------------------
  fetch("/api/mail/providers")
    .then(r => r.json())
    .then(p => {
      $("#mProvider").replaceChildren(
        ...Object.entries(p).map(([k, v]) =>
          el(
            "option",
            { value: k },
            v
          )
        )
      );
    })
    .catch(() => {
      $("#mErr").textContent =
        "Could not load mail providers.";
    });


  $("#mProvider").addEventListener(
    "change",
    e => {
      $("#mHostRow").hidden =
        e.target.value !== "custom";
    }
  );


  // ------------------------------------------------------------
  // Build one email card.
  // ------------------------------------------------------------
  function card(m) {

    const [label, lvl] =
      VERDICT[m.verdict]
      || ["Unknown", "Low"];


    // Evidence
    const ev =
      (m.evidence || [])
        .slice(0, 6)
        .map(e =>
          el(
            "li",
            {},
            el(
              "span",
              {
                class: "dot " + e.severity
              }
            ),
            el(
              "span",
              {},
              e.text
            )
          )
        );


    // Attachments
    const atts =
      (m.attachments || [])
        .map(a =>
          el(
            "li",
            {},

            el(
              "span",
              {
                class: "pill " + a.level
              },
              a.score + ""
            ),

            " ",

            el(
              "span",
              {},
              `${a.filename} (${a.kind}, ${fmtSize(a.size_bytes)})`
              +
              (
                a.scanned
                  ? ""
                  : " - not analysed"
              )
            )
          )
        );


    // Security facts
    const facts = [];


    if (m.auth) {
      facts.push(
        AUTH[m.auth.state] || ""
      );
    }


    if (
      m.ai_text_likelihood != null
    ) {
      facts.push(
        "AI-written style: "
        +
        Math.round(
          m.ai_text_likelihood * 100
        )
        +
        "%"
      );
    }


    if (
      m.ai_media_flagged
      &&
      m.ai_media_flagged.length
    ) {
      facts.push(
        "Possible AI/manipulated media: "
        +
        m.ai_media_flagged.join(", ")
      );
    }


    // ----------------------------------------------------------
    // New / unread or older / read badge.
    // ----------------------------------------------------------
    const statusLabel =
      m.is_unread
        ? "NEW / UNREAD"
        : "OLDER / READ";

    const statusClass =
      m.is_unread
        ? "unread"
        : "read";


    const d =
      el(
        "details",
        {
          class:
            "mailcard " + lvl
        },

        el(
          "summary",
          {},

          el(
            "span",
            {
              class:
                "pill " + lvl
            },
            label
          ),

          " ",

          el(
            "strong",
            {},
            m.subject
              || "(no subject)"
          ),

          " ",

          el(
            "span",
            {
              class:
                "pill " + statusClass
            },
            statusLabel
          ),

          el(
            "span",
            {
              class: "muted"
            },
            "  "
            +
            (
              m.from_name
                ? m.from_name + " "
                : ""
            )
            +
            (
              m.from_addr
                ? "<" + m.from_addr + ">"
                : ""
            )
          ),

          el(
            "span",
            {
              class:
                "muted mail-date"
            },
            "  Sent: "
            +
            formatDate(
              m.date
            )
          ),

          el(
            "span",
            {
              class: "score"
            },
            m.verdict === "skipped"
              ? ""
              : m.score + "/100"
          )
        ),

        el(
          "div",
          {
            class: "rbody"
          },

          el(
            "p",
            {},
            el(
              "strong",
              {},
              m.verdict_text
                || ""
            )
          ),

          // Show sent date/time again inside
          // the expanded message.
          el(
            "p",
            {
              class: "muted"
            },
            "Sent: "
            +
            formatDate(
              m.date
            )
          ),

          // Display the actual email message safely as plain text.
          el(
            "div",
            {
              class: "sec email-content"
            },
            el(
              "h4",
              {},
              "Email Content"
            ),
            el(
              "pre",
              {
                class: "mail-message-body"
              },
              m.body || "No readable message content was returned by the mailbox scanner."
            )
          ),


          facts.length
            ? el(
                "ul",
                {
                  class: "recs"
                },

                facts
                  .filter(Boolean)
                  .map(f =>
                    el(
                      "li",
                      {},
                      f
                    )
                  )
              )
            : null,

          ev.length
            ? el(
                "div",
                {
                  class: "sec"
                },

                el(
                  "h4",
                  {},
                  "What we found"
                ),

                el(
                  "ul",
                  {
                    class: "ev"
                  },
                  ev
                )
              )
            : null,

          atts.length
            ? el(
                "div",
                {
                  class: "sec"
                },

                el(
                  "h4",
                  {},
                  "Attachments"
                ),

                el(
                  "ul",
                  {
                    class: "ev"
                  },
                  atts
                )
              )
            : null,

          m.recommendations
            ? el(
                "div",
                {
                  class: "sec"
                },

                el(
                  "h4",
                  {},
                  "What to do"
                ),

                el(
                  "ul",
                  {
                    class: "recs"
                  },

                  m.recommendations
                    .map(x =>
                      el(
                        "li",
                        {},
                        x
                      )
                    )
                )
              )
            : null,

          m.id
            ? el(
                "div",
                {
                  class: "actions"
                },

                el(
                  "a",
                  {
                    href:
                      "/api/report/"
                      +
                      encodeURIComponent(
                        m.id
                      )
                  },

                  el(
                    "button",
                    {
                      class: "ghost",
                      type: "button"
                    },
                    "Download report (JSON)"
                  )
                )
              )
            : null
        )
      );


    // Automatically open dangerous messages.
    if (m.verdict === "fake") {
      d.open = true;
    }

    return d;
  }


  // ------------------------------------------------------------
  // Create a section for New/Unread or Older/Read messages.
  // ------------------------------------------------------------
  function makeSection(
    title,
    messages
  ) {

    return el(
      "section",
      {
        class: "mail-section"
      },

      el(
        "h3",
        {},
        `${title} (${messages.length})`
      ),

      ...messages.map(card)
    );
  }


  // ------------------------------------------------------------
  // Scan mailbox button.
  // ------------------------------------------------------------
  $("#mScan").addEventListener(
    "click",
    async () => {

      const btn =
        $("#mScan");

      $("#mErr").textContent = "";

      $("#mEmpty").hidden = true;

      $("#mList").hidden = true;


      const body = {
        provider:
          $("#mProvider").value,

        host:
          $("#mHost").value,

        user:
          $("#mUser").value,

        password:
          $("#mPass").value,

        limit:
          +$("#mLimit").value
      };


      // Only show the loading/analysing
      // message while a scan is actually running.
      btn.disabled = true;

      $("#mLoading").hidden = false;


      try {

        const r =
          await fetch(
            "/api/mail/scan",
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json"
              },

              body:
                JSON.stringify(body)
            }
          );


        const j =
          await r.json();


        if (!r.ok) {
          throw new Error(
            j.error
            || "Scan failed"
          );
        }


        // Clear password immediately.
        $("#mPass").value = "";


        const messages =
          j.messages || [];


        // ------------------------------------------------------
        // Separate unread from read.
        // ------------------------------------------------------
        const unread =
          messages.filter(
            m =>
              m.is_unread === true
          );


        const older =
          messages.filter(
            m =>
              m.is_unread !== true
          );


        // ------------------------------------------------------
        // Count verdicts.
        // ------------------------------------------------------
        const c = {
          fake: 0,
          suspicious: 0,
          genuine: 0,
          unverified: 0,
          skipped: 0
        };


        messages.forEach(m => {

          if (
            c[m.verdict]
            != null
          ) {
            c[m.verdict]++;
          }

        });


        // ------------------------------------------------------
        // No messages.
        //
        // In this situation we DO NOT display "Analysing..."
        // after the scan has finished.
        // ------------------------------------------------------
        if (
          messages.length === 0
        ) {

          $("#mList")
            .replaceChildren();

          $("#mList").hidden = true;

          $("#mEmpty").textContent =
            "No emails were found in this folder. " +
            "There is nothing to analyse.";

          $("#mEmpty").hidden = false;

          return;
        }


        // ------------------------------------------------------
        // Summary
        // ------------------------------------------------------
        const summary =
          el(
            "p",
            {
              class: "muted"
            },

            `${messages.length} messages: `
            +
            `${unread.length} new/unread, `
            +
            `${older.length} older/read. `
            +
            `${c.fake} fake, `
            +
            `${c.suspicious} suspicious, `
            +
            `${c.unverified} unverified, `
            +
            `${c.genuine} genuine, `
            +
            `${c.skipped} skipped.`
          );


        const sections = [
          summary
        ];


        // ------------------------------------------------------
        // New / unread messages first.
        // ------------------------------------------------------
        if (
          unread.length
        ) {

          sections.push(
            makeSection(
              "New / Unread Emails",
              unread
            )
          );
        }


        // ------------------------------------------------------
        // Older / read messages second.
        // ------------------------------------------------------
        if (
          older.length
        ) {

          sections.push(
            makeSection(
              "Older / Read Emails",
              older
            )
          );
        }


        $("#mList")
          .replaceChildren(
            ...sections
          );

        $("#mList").hidden = false;

        $("#mEmpty").hidden = true;

      } catch (e) {

        // Never leave the password
        // sitting in the page.
        $("#mPass").value = "";

        $("#mErr").textContent =
          e.message;

        $("#mList").hidden = true;

        $("#mEmpty").hidden = false;

      } finally {

        // Loading indicator exists ONLY
        // during the actual request.
        btn.disabled = false;

        $("#mLoading").hidden = true;
      }

    }
  );

})();
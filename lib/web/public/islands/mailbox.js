// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Message list conveniences. Everything the list does without this file
// keeps working: the checkboxes select, the buttons submit, the subject
// links open. This adds a select-all control and keyboard movement for
// readers who would rather not reach for the pointer.
//
// The select-all control is built with createElement and textContent
// rather than by assigning markup, because the page is served under a
// policy that requires a Trusted Types sink for the latter.

(function () {
  var form = document.querySelector('form[data-island="mailbox"]');
  if (!form) return;

  var rows = Array.prototype.slice.call(form.querySelectorAll(".msg"));
  if (rows.length === 0) return;

  var picks = rows.map(function (row) { return row.querySelector("input[type='checkbox']"); });
  var cursor = 0;

  // ---- Select all -------------------------------------------------

  var bar = form.querySelector(".bulkbar");
  if (bar) {
    var wrap = document.createElement("span");
    wrap.className = "inline-form";

    var box = document.createElement("input");
    box.type = "checkbox";
    box.id = "select-all";

    var label = document.createElement("label");
    label.setAttribute("for", "select-all");
    label.className = "topnav-link";
    label.textContent = "All";

    box.addEventListener("change", function () {
      for (var i = 0; i < picks.length; i += 1) {
        if (picks[i]) picks[i].checked = box.checked;
      }
    });

    wrap.appendChild(box);
    wrap.appendChild(label);
    bar.insertBefore(wrap, bar.firstChild);
  }

  // ---- Keyboard movement ------------------------------------------

  function focusRow(index) {
    if (index < 0) index = 0;
    if (index > rows.length - 1) index = rows.length - 1;
    cursor = index;
    var link = rows[cursor].querySelector(".msg-body");
    if (link) link.focus();
  }

  function isTyping(target) {
    if (!target || !target.tagName) return false;
    var tag = target.tagName.toLowerCase();
    return tag === "input" || tag === "textarea" || tag === "select" || target.isContentEditable;
  }

  document.addEventListener("keydown", function (event) {
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    if (isTyping(event.target)) return;

    if (event.key === "j" || event.key === "ArrowDown") {
      event.preventDefault();
      focusRow(cursor + 1);
      return;
    }
    if (event.key === "k" || event.key === "ArrowUp") {
      event.preventDefault();
      focusRow(cursor - 1);
      return;
    }
    if (event.key === "x") {
      event.preventDefault();
      var pick = picks[cursor];
      if (pick) pick.checked = !pick.checked;
      return;
    }
    if (event.key === "/") {
      var search = document.getElementById("q");
      if (search) { event.preventDefault(); search.focus(); }
    }
  });

  // Keep the cursor on whichever row the reader actually reached, so
  // tabbing and the keys agree about where they are.
  for (var r = 0; r < rows.length; r += 1) {
    (function (index) {
      rows[index].addEventListener("focusin", function () { cursor = index; });
    }(r));
  }
}());

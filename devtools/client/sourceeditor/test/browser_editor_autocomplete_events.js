/* vim: set ts=2 et sw=2 tw=80: */
/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const {InspectorFront} = require("devtools/shared/fronts/inspector");
const TEST_URI = "data:text/html;charset=UTF-8,<html><body><bar></bar>" +
                 "<div id='baz'></div><body></html>";

add_task(async function() {
  await addTab(TEST_URI);
  await runTests();
});

async function runTests() {
  let target = TargetFactory.forTab(gBrowser.selectedTab);
  await target.makeRemote();
  let inspector = InspectorFront(target.client, target.form);
  let walker = await inspector.getWalker();
  let {ed, win, edWin} = await setup(null, {
    autocomplete: true,
    mode: Editor.modes.css,
    autocompleteOpts: {walker: walker, cssProperties: getClientCssProperties()}
  });
  await testMouse(ed, edWin);
  await testKeyboard(ed, edWin);
  await testKeyboardCycle(ed, edWin);
  await testKeyboardCycleForPrefixedString(ed, edWin);
  await testKeyboardCSSComma(ed, edWin);
  teardown(ed, win);
}

async function testKeyboard(ed, win) {
  ed.focus();
  ed.setText("b");
  ed.setCursor({line: 1, ch: 1});

  let popupOpened = ed.getAutocompletionPopup().once("popup-opened");

  let autocompleteKey =
    Editor.keyFor("autocompletion", { noaccel: true }).toUpperCase();
  EventUtils.synthesizeKey("VK_" + autocompleteKey, { ctrlKey: true }, win);

  info("Waiting for popup to be opened");
  await popupOpened;

  EventUtils.synthesizeKey("VK_RETURN", { }, win);
  is(ed.getText(), "bar", "Editor text has been updated");
}

async function testKeyboardCycle(ed, win) {
  ed.focus();
  ed.setText("b");
  ed.setCursor({line: 1, ch: 1});

  let popupOpened = ed.getAutocompletionPopup().once("popup-opened");

  let autocompleteKey =
    Editor.keyFor("autocompletion", { noaccel: true }).toUpperCase();
  EventUtils.synthesizeKey("VK_" + autocompleteKey, { ctrlKey: true }, win);

  info("Waiting for popup to be opened");
  await popupOpened;

  EventUtils.synthesizeKey("VK_DOWN", { }, win);
  is(ed.getText(), "bar", "Editor text has been updated");

  EventUtils.synthesizeKey("VK_DOWN", { }, win);
  is(ed.getText(), "body", "Editor text has been updated");

  EventUtils.synthesizeKey("VK_DOWN", { }, win);
  is(ed.getText(), "#baz", "Editor text has been updated");
}

async function testKeyboardCycleForPrefixedString(ed, win) {
  ed.focus();
  ed.setText("#b");
  ed.setCursor({line: 1, ch: 2});

  let popupOpened = ed.getAutocompletionPopup().once("popup-opened");

  let autocompleteKey =
    Editor.keyFor("autocompletion", { noaccel: true }).toUpperCase();
  EventUtils.synthesizeKey("VK_" + autocompleteKey, { ctrlKey: true }, win);

  info("Waiting for popup to be opened");
  await popupOpened;

  EventUtils.synthesizeKey("VK_DOWN", { }, win);
  is(ed.getText(), "#baz", "Editor text has been updated");
}

async function testKeyboardCSSComma(ed, win) {
  ed.focus();
  ed.setText("b");
  ed.setCursor({line: 1, ch: 1});

  let isPopupOpened = false;
  let popupOpened = ed.getAutocompletionPopup().once("popup-opened");
  popupOpened.then(() => {
    isPopupOpened = true;
  });

  EventUtils.synthesizeKey(",", { }, win);

  await wait(500);

  ok(!isPopupOpened, "Autocompletion shouldn't be opened");
}

async function testMouse(ed, win) {
  ed.focus();
  ed.setText("b");
  ed.setCursor({line: 1, ch: 1});

  let popupOpened = ed.getAutocompletionPopup().once("popup-opened");

  let autocompleteKey =
    Editor.keyFor("autocompletion", { noaccel: true }).toUpperCase();
  EventUtils.synthesizeKey("VK_" + autocompleteKey, { ctrlKey: true }, win);

  info("Waiting for popup to be opened");
  await popupOpened;
  ed.getAutocompletionPopup()._list.children[2].click();
  is(ed.getText(), "#baz", "Editor text has been updated");
}

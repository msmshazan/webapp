'use strict';
import './../css/main.css';
const m = require("mithril");

const root = document.body;

function main() {
    m.render(root,m("h1", "My first app"));
    m.render(root,m("div","My Second app"));
    m.render(root,m("div","My third app"));
}

window.onload = main;
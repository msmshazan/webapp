'use strict';
import styles from './../css/index.css';
import image from './../admin-tool.png';
const m = require("mithril");

const root = document.body;

function main() {
    m.render(root, m("div",
        [
            m("h1", "My first app"),
            m("img", { src: image }),
            m("div", "My third app"),
            m("button.button","Hello"),
            m("div","Tell")
        ]
    ));
}

window.onload = main;
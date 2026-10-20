// LiteBox v1.0.8 —— vendor 自 https://github.com/OblivionOcean/LiteBox（MIT License）。
// 纯原生 JS 图片灯箱（<dialog> + CSS transform），零外部依赖，符合本仓「零框架/零 npm
// 依赖」红线。除以下三处**受控适配**外与上游逐字节一致，便于后续同步（改任一处请同步登记）：
//   ① 文件末尾实例化加 readyState 守卫（本仓由 app.js 进页时动态注入本脚本，
//      DOMContentLoaded 早已发生——check-idle-scripts 门禁要求，与 updater-ui.js 同款）；
//   ② click() 的 total 计数改为「按灯箱图是否在 range 内二分」（range 收窄后原「减 1」
//      少算一张，最后一张之后无法回绕到第一张）；
//   ③ navigate() 的翻页目标从 document 改为 range（否则会翻到主窗其它页的 <img>）；
//   ④ 构造模板里灯箱自带 img 的空 src 换成 1x1 透明占位——空 src 被浏览器解析成当前页
//      URL，启动即触发一次必然失败的资源请求（真机日志 IMG http://127.0.0.1:1430/）。
// 本仓消费方式见 cleanup.js 的 openPreview：range 收窄到预览容器，全局 img 点击不劫持。

class Litebox {
    constructor() {
        this.dialog = document.createElement("dialog");
        document.body.appendChild(this.dialog);
        this.dialog.classList.add("litebox");
        this.dialog.innerHTML = `<div class="counter">1/4</div><div class="zoom-level">缩放:100%</div><div class="lightbox-container"><img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"alt="灯箱图片"class="lightbox-image"id="lightbox-image"><div class="caption">图片描述</div></div><div class="lightbox-controls"><button id="prev-btn"data-tip="上一张 (左箭头)"><svg viewBox="0 0 16 16"><path fill-rule="evenodd"d="M12 8a.5.5 0 0 1-.5.5H5.707l2.147 2.146a.5.5 0 0 1-.708.708l-3-3a.5.5 0 0 1 0-.708l3-3a.5.5 0 1 1 .708.708L5.707 7.5H11.5a.5.5 0 0 1 .5.5"/></svg></button><button id="next-btn"data-tip="下一张 (右箭头)"><svg viewBox="0 0 16 16"><path fill-rule="evenodd"d="M4 8a.5.5 0 0 1 .5-.5h5.793L8.146 5.354a.5.5 0 1 1 .708-.708l3 3a.5.5 0 0 1 0 .708l-3 3a.5.5 0 0 1-.708-.708L10.293 8.5H4.5A.5.5 0 0 1 4 8"/></svg></button></div><div class="nav-controls"><button id="zoom-in-btn"data-tip="放大 (+键)"><svg viewBox="0 0 16 16"><path d="M8 4a.5.5 0 0 1 .5.5v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3A.5.5 0 0 1 8 4"/></svg></button><button id="zoom-out-btn"data-tip="缩小 (-键)"><svg viewBox="0 0 16 16"><path d="M4 8a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 0 1h-7A.5.5 0 0 1 4 8"/></svg></button><button id="rotate-btn"data-tip="旋转 (R键)"><svg viewBox="-4 -4 24 24"><path fill-rule="evenodd"d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2z"/><path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466"/></svg></button><button id="reset-btn"data-tip="重置 (0键)"><svg viewBox="-8 -8 32 32"><path fill-rule="evenodd"d="M5.828 10.172a.5.5 0 0 0-.707 0l-4.096 4.096V11.5a.5.5 0 0 0-1 0v3.975a.5.5 0 0 0 .5.5H4.5a.5.5 0 0 0 0-1H1.732l4.096-4.096a.5.5 0 0 0 0-.707m4.344 0a.5.5 0 0 1 .707 0l4.096 4.096V11.5a.5.5 0 1 1 1 0v3.975a.5.5 0 0 1-.5.5H11.5a.5.5 0 0 1 0-1h2.768l-4.096-4.096a.5.5 0 0 1 0-.707m0-4.344a.5.5 0 0 0 .707 0l4.096-4.096V4.5a.5.5 0 1 0 1 0V.525a.5.5 0 0 0-.5-.5H11.5a.5.5 0 0 0 0 1h2.768l-4.096 4.096a.5.5 0 0 0 0 .707m-4.344 0a.5.5 0 0 1-.707 0L1.025 1.732V4.5a.5.5 0 0 1-1 0V.525a.5.5 0 0 1 .5-.5H4.5a.5.5 0 0 1 0 1H1.732l4.096 4.096a.5.5 0 0 1 0 .707"/></svg></button><button id="close-btn"data-tip="关闭 (ESC)"><svg viewBox="0 0 16 16"><path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708"/></svg></button></div>`
        this.range = document;
        this.clickHandler = this.click.bind(this);
        this.initEvents();
    }

    initEvents() {
        this.setRange();
        this.getElem("#close-btn").addEventListener('click', this.close.bind(this));
        this.getElem("#zoom-out-btn").addEventListener('click', () => this.zoom(-0.3));
        this.getElem("#zoom-in-btn").addEventListener('click', () => this.zoom(0.3));
        this.getElem("#rotate-btn").addEventListener('click', this.rotate.bind(this));
        this.getElem("#reset-btn").addEventListener('click', this.resetLightbox.bind(this));
        this.getElem("#prev-btn").addEventListener('click', () => this.navigate(-1));
        this.getElem("#next-btn").addEventListener('click', () => this.navigate(1));
        // 点击灯箱背景关闭
        this.dialog.addEventListener('click', (e) => {
            if (e.target === this.dialog) {
                this.close();
            }
        });
        // 键盘快捷键
        document.addEventListener('keydown', (e) => {
            if (!this.dialog.hasAttribute('open')) return; // 如果灯箱未打开则忽略按键事件
            e.preventDefault();
            switch (e.key) {
                case 'Escape':
                    this.close();
                    break;
                case 'ArrowLeft':
                    this.navigate(-1);
                    break;
                case 'ArrowRight':
                    this.navigate(1);
                    break;
                case '+': case '=':
                    this.zoom(0.3);
                    break;
                case '-': case '_':
                    this.zoom(-0.3);
                    break;
                case '0':
                    this.resetLightbox();
                    break;
                case 'r': case 'R':
                    this.rotate();
                    break;
            }
        });
    }

    click(e) {
        e = e.target
        if (e.tagName == 'IMG' && e.className != 'lightbox-img' && e.src) {
            let allImg = this.range.getElementsByTagName("img")
            // 本仓受控适配②：range 收窄到预览容器后，灯箱自身的 img（挂在 body 的
            // dialog 里）不再位于 range 内，「减去灯箱图本身」会把总数少算 1——
            // 表现为最后一张之后无法回绕到第一张。按「灯箱图是否在 range 内」二分。
            const lightboxImg = this.getElem('.lightbox-image');
            const inRange = lightboxImg ? this.range.contains(lightboxImg) : false;
            this.total = allImg.length - (inRange ? 1 : 0);
            this.current = Array.from(allImg).indexOf(e) + 1;
            if (e.classList.contains('lightbox-image')) return; // 防止灯箱图片被点击
            if (e.preventDefault) e.preventDefault();
            this.set(e.getAttribute("data-src") || e.src, e.getAttribute("data-caption") || e.alt || e.title || "", e.alt || e.title || "");
            this.show();
        }
    }

    getElem(selector) {
        return this.dialog.querySelector(selector);
    }

    show() {
        if (!this.dialog.hasAttribute('open')) {
            if (this.dialog.showModal) {
                this.dialog.showModal();
                this.dialog.setAttribute('open', '');
            }
        }
    }

    close() {
        if (this.dialog.close) {
            this.dialog.close();
        }
        this.dialog.removeAttribute('open');
        this.resetLightbox();
    }

    set(url, caption, title) {
        this.getElem('.lightbox-image').style.opacity = '0';
        this.getElem('.lightbox-image').src = url;
        this.getElem('.lightbox-image').title = title || '';
        this.getElem('.caption').textContent = caption || '';
        this.getElem('.lightbox-image').onload = () => {
            this.getElem('.lightbox-image').style.opacity = '1';
        };
        this.getElem('.lightbox-image').onerror = () => {
            this.getElem('.caption').textContent = '图片加载失败';
            this.resetLightbox();
        };
        this.resetLightbox();
    }

    resetLightbox() {
        this.getElem('.counter').textContent = `${this.currentIndex || 0} / ${this.total || 0}`;
        this.scale = 1;
        this.zoom()
        this.dialog.style.setProperty('--rotate', '0deg');
    }

    zoom(amount) {
        this.scale = Math.max(0.1, Math.min(5, (this.scale || 0) + (amount || 0)));
        this.dialog.style.setProperty('--scale', this.scale);
        this.getElem('.zoom-level').textContent = `缩放: ${Math.round(this.scale * 100)}%`;
    }

    rotate() {
        this.rotation = ((this.rotation || 0) + 90) % 360;
        this.dialog.style.setProperty('--rotate', `${this.rotation}deg`);
    }

    navigate(direction) {
        this.currentIndex = (this.currentIndex || 0) + direction;
        if (this.currentIndex <= 0) {
            this.currentIndex = this.total - 1;
        } else if (this.currentIndex > this.total) {
            this.currentIndex = 0;
        }
        // 本仓受控适配③：翻页目标必须在 **range 内**找——原样用 document 的话，
        // range 收窄后会翻到主窗其它页的 <img>（应用图标回退、壁纸预览等）。
        const targetImage = this.range.getElementsByTagName("img")[this.currentIndex - 1];
        if (targetImage) {
            this.click({ target: targetImage, currentIndex: this.currentIndex });
        }
    }

    setRange(dom) {
        this.range.removeEventListener('click', this.clickHandler);
        this.range = dom || document;
        this.range.addEventListener('click', this.clickHandler);
    }
}

// 上游原样是只挂 DOMContentLoaded；本仓由 app.js 进页时**动态注入**本脚本，
// 届时 DOMContentLoaded 早已发生，注册等于永不执行（check-idle-scripts 门禁会红）。
// 加 readyState 守卫与上游 updater-ui.js 同款姿势。
if (typeof dontLoadLiteBox == "undefined") {
    const bootLiteBox = () => {
        if (!window.liteBox) liteBox = window.liteBox = new Litebox();
    };
    if (document.readyState === 'loading') {
        document.addEventListener("DOMContentLoaded", bootLiteBox);
    } else {
        bootLiteBox();
    }
}

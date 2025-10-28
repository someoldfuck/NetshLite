import tkinter as tk

def install_shortcuts(root: tk.Tk):
    """
    Шорткати працюють у будь-якій розкладці (укр/рос/англ),
    перевіряємо keycode (Windows VK): A=65, C=67, V=86, X=88.
    Додаємо Ctrl+Insert / Shift+Insert / Shift+Delete. ПКМ-меню для Entry/Text.
    """
    KEY_A, KEY_C, KEY_V, KEY_X = 65, 67, 86, 88

    # Entry
    def _entry_ctrl_handler(e):
        kc = e.keycode
        if kc == KEY_C:
            e.widget.event_generate("<<Copy>>");  return "break"
        if kc == KEY_V:
            e.widget.event_generate("<<Paste>>"); return "break"
        if kc == KEY_X:
            e.widget.event_generate("<<Cut>>");   return "break"
        if kc == KEY_A:
            e.widget.select_range(0, 'end'); e.widget.icursor('end'); return "break"
        return None

    root.bind_class("Entry", "<Control-KeyPress>", _entry_ctrl_handler)
    root.bind_class("Entry", "<Control-Insert>",  lambda e: (e.widget.event_generate("<<Copy>>"),  "break"))
    root.bind_class("Entry", "<Shift-Insert>",    lambda e: (e.widget.event_generate("<<Paste>>"), "break"))
    root.bind_class("Entry", "<Shift-Delete>",    lambda e: (e.widget.event_generate("<<Cut>>"),   "break"))

    # Text / ScrolledText
    def _text_ctrl_handler(e):
        kc = e.keycode
        if kc == KEY_C:
            e.widget.event_generate("<<Copy>>");  return "break"
        if kc == KEY_V:
            e.widget.event_generate("<<Paste>>"); return "break"
        if kc == KEY_X:
            e.widget.event_generate("<<Cut>>");   return "break"
        if kc == KEY_A:
            e.widget.tag_add("sel", "1.0", "end-1c"); return "break"
        return None

    root.bind_class("Text", "<Control-KeyPress>", _text_ctrl_handler)
    root.bind_class("Text", "<Control-Insert>",  lambda e: (e.widget.event_generate("<<Copy>>"),  "break"))
    root.bind_class("Text", "<Shift-Insert>",    lambda e: (e.widget.event_generate("<<Paste>>"), "break"))
    root.bind_class("Text", "<Shift-Delete>",    lambda e: (e.widget.event_generate("<<Cut>>"),   "break"))

    # Контекстне меню
    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Вирізати",  command=lambda: root.focus_get().event_generate("<<Cut>>"))
    menu.add_command(label="Копіювати", command=lambda: root.focus_get().event_generate("<<Copy>>"))
    menu.add_command(label="Вставити",  command=lambda: root.focus_get().event_generate("<<Paste>>"))
    menu.add_separator()
    menu.add_command(label="Виділити все", command=lambda: root.focus_get().event_generate("<Control-KeyPress>", keycode=65))

    def show_menu(event):
        w = event.widget
        if isinstance(w, (tk.Entry, tk.Text)):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

    root.bind_class("Entry", "<Button-3>", show_menu)
    root.bind_class("Text",  "<Button-3>", show_menu)

def append_log(widget: tk.Text, msg: str):
    widget.configure(state='normal')
    widget.insert('end', msg + "\n")
    widget.configure(state='disabled')
    widget.see('end')

def clear_log(widget: tk.Text, status_var):
    widget.configure(state='normal')
    widget.delete('1.0', 'end')
    widget.configure(state='disabled')
    status_var.set("Лог очищено 🧹")

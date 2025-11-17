import json
import os
import base64
import secrets
import string
from pathlib import Path
from tkinter import *
from tkinter import simpledialog, messagebox, ttk, font
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import pyperclip

# CONFIG 
VAULT_FOLDER = Path(os.getenv("APPDATA")) / "MyPasswordManager"
VAULT_FOLDER.mkdir(exist_ok=True)
VAULT_PATH = VAULT_FOLDER / "vault.bin"

KDF_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_LEN = 32

def derive_key(master_password: str, salt: bytes) -> bytes:
    return PBKDF2(master_password, salt, dkLen=KEY_LEN, count=KDF_ITERATIONS)

def encrypt_database(db: dict, master_password: str) -> bytes:
    plaintext = json.dumps(db).encode("utf-8")
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(master_password, salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    packaged = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    return json.dumps(packaged).encode("utf-8")

def decrypt_database(blob: bytes, master_password: str) -> dict:
    packaged = json.loads(blob.decode("utf-8"))
    salt = base64.b64decode(packaged["salt"])
    nonce = base64.b64decode(packaged["nonce"])
    tag = base64.b64decode(packaged["tag"])
    ciphertext = base64.b64decode(packaged["ciphertext"])
    key = derive_key(master_password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext.decode("utf-8"))

def load_vault(master_password: str) -> dict:
    if not VAULT_PATH.exists():
        return {"entries": []}
    blob = VAULT_PATH.read_bytes()
    try:
        return decrypt_database(blob, master_password)
    except Exception as e:
        raise ValueError("Wrong master password or corrupted vault.") from e

def save_vault(db: dict, master_password: str):
    blob = encrypt_database(db, master_password)
    VAULT_PATH.write_bytes(blob)

def generate_password(length=16, use_symbols=True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>?/|"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ---------- UI ----------
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        root.title("🔐 Password Manager")
        root.geometry("1200x700")
        root.minsize(1000, 600)
        root.configure(bg="#f5f7fa")
        
        # Center window on screen
        root.update_idletasks()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width // 2) - (1200 // 2)
        y = (screen_height // 2) - (700 // 2)
        root.geometry(f"1200x700+{x}+{y}")
        
        # Color scheme
        self.colors = {
            'bg_main': '#f5f7fa',
            'bg_white': '#ffffff',
            'bg_sidebar': '#1e3a8a',
            'blue_primary': '#2563eb',
            'blue_light': '#3b82f6',
            'blue_lighter': '#60a5fa',
            'blue_dark': '#1e40af',
            'blue_hover': '#1d4ed8',
            'text_dark': '#1f2937',
            'text_gray': '#6b7280',
            'text_light': '#9ca3af',
            'success': '#10b981',
            'danger': '#ef4444',
            'warning': '#f59e0b',
            'border': '#e5e7eb',
            'border_focus': '#3b82f6'
        }
        
        style = ttk.Style()
        style.theme_use('clam')
        
        self.font_title = font.Font(family="Segoe UI", size=14, weight="bold")
        self.font_subtitle = font.Font(family="Segoe UI", size=11, weight="bold")
        self.font_body = font.Font(family="Segoe UI", size=10)
        self.font_small = font.Font(family="Segoe UI", size=9)
        
        # Configure ttk button styles
        style.configure('Primary.TButton', 
                       background=self.colors['blue_primary'],
                       foreground='white', borderwidth=0,
                       focuscolor='none', padding=(12, 6),
                       font=('Segoe UI', 9, 'bold'))
        style.map('Primary.TButton', background=[('active', self.colors['blue_hover'])])
        
        style.configure('Secondary.TButton',
                       background=self.colors['bg_white'],
                       foreground=self.colors['text_dark'],
                       borderwidth=1, focuscolor='none',
                       padding=(10, 6), font=('Segoe UI', 9))
        style.map('Secondary.TButton', background=[('active', self.colors['bg_main'])])
        
        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white', borderwidth=0,
                       focuscolor='none', padding=(12, 6),
                       font=('Segoe UI', 9, 'bold'))
        style.map('Success.TButton', background=[('active', '#059669')])
        
        style.configure('Danger.TButton',
                       background=self.colors['danger'],
                       foreground='white', borderwidth=0,
                       focuscolor='none', padding=(10, 6),
                       font=('Segoe UI', 9))
        style.map('Danger.TButton', background=[('active', '#dc2626')])
        
        style.configure('Sidebar.TButton',
                       background=self.colors['bg_sidebar'],
                       foreground='white', borderwidth=0,
                       focuscolor='none', padding=(15, 12),
                       font=('Segoe UI', 10))
        style.map('Sidebar.TButton', background=[('active', self.colors['blue_dark'])])
        
        # Master password dialog with retry loop
        attempts = 0
        MAX_ATTEMPTS = 5
        while True:
            pwd = self.show_master_password_dialog()
            if not pwd:
                root.destroy()
                return
            try:
                self.db = load_vault(pwd)
                self.master_password = pwd
                break
            except ValueError:
                attempts += 1
                remaining = MAX_ATTEMPTS - attempts
                if remaining <= 0:
                    messagebox.showerror("Authentication Failed", "Too many failed attempts. Exiting.")
                    root.destroy()
                    return
                messagebox.showerror(
                    "Authentication Failed",
                    f"Incorrect master password or corrupted vault.\nPlease try again. ({remaining} attempt(s) left)"
                )
    
        root.lift()
        root.focus_force()

        # LEFT SIDEBAR
        sidebar = Frame(root, bg=self.colors['bg_sidebar'], width=280)
        sidebar.pack(side=LEFT, fill=Y)
        sidebar.pack_propagate(False)

        brand_frame = Frame(sidebar, bg=self.colors['bg_sidebar'], pady=25, padx=20)
        brand_frame.pack(fill=X)
        Label(brand_frame, text="🔐 Password Manager", font=self.font_title, 
              bg=self.colors['bg_sidebar'], fg='white').pack()
        Label(brand_frame, text="Secure & Simple", font=self.font_small,
              bg=self.colors['bg_sidebar'], fg=self.colors['blue_lighter']).pack(pady=(3, 0))
        
        search_frame = Frame(sidebar, bg=self.colors['bg_sidebar'], padx=15)
        search_frame.pack(fill=X, pady=(0, 15))
        search_container = Frame(search_frame, bg='white')
        search_container.pack(fill=X)
        Label(search_container, text="🔍", bg='white', font=self.font_body).pack(side=LEFT, padx=(12, 8))
        self.search_var = StringVar()
        self.search_var.trace('w', lambda *args: self.refresh_listbox())
        search_entry = Entry(search_container, textvariable=self.search_var, font=self.font_body,
                            bg='white', fg=self.colors['text_dark'], relief='flat',
                            insertbackground=self.colors['blue_primary'], borderwidth=0)
        search_entry.pack(side=LEFT, fill=X, expand=True, ipady=10, padx=(0, 12))
        
        Label(sidebar, text="YOUR PASSWORDS", font=self.font_small,
              bg=self.colors['bg_sidebar'], fg=self.colors['blue_lighter'], anchor=W).pack(fill=X, padx=20, pady=(10, 8))
        
        listbox_container = Frame(sidebar, bg=self.colors['bg_sidebar'], padx=15)
        listbox_container.pack(fill=BOTH, expand=True, pady=(0, 15))
        list_frame = Frame(listbox_container, bg='white')
        list_frame.pack(fill=BOTH, expand=True)
        scrollbar = Scrollbar(list_frame, width=12)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.listbox = Listbox(list_frame, font=self.font_body,
                              bg='white', fg=self.colors['text_dark'],
                              selectbackground=self.colors['blue_light'], selectforeground='white',
                              borderwidth=0, highlightthickness=0, activestyle='none', 
                              yscrollcommand=scrollbar.set, relief='flat')
        self.listbox.pack(side=LEFT, fill=BOTH, expand=True, padx=2, pady=2)
        scrollbar.config(command=self.listbox.yview)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)
        self.listbox.bind('<Double-Button-1>', self.on_double_click)
        self.listbox.bind('<Button-3>', self.show_list_context_menu)
        self.list_menu = Menu(self.listbox, tearoff=0)
        self.list_menu.add_command(label="Edit", command=self.context_edit_selected)
        self.list_menu.add_command(label="Delete", command=self.context_delete_selected)

        btn_container = Frame(sidebar, bg=self.colors['bg_sidebar'], padx=15, pady=20)
        btn_container.pack(side=BOTTOM, fill=X)
        ttk.Button(btn_container, text="➕ New Password", command=self.new_entry, 
                  style='Primary.TButton').pack(fill=X, pady=(0, 10))
        ttk.Button(btn_container, text="💾 Save Vault", command=self.save_vault_ui, 
                  style='Success.TButton').pack(fill=X, pady=(0, 10))
        ttk.Button(btn_container, text="🔑 Master Password", 
                  command=self.change_master_password, 
                  style='Sidebar.TButton').pack(fill=X)

        # MAIN CONTENT AREA 
        main_area = Frame(root, bg=self.colors['bg_main'])
        main_area.pack(side=RIGHT, expand=True, fill=BOTH)
        header = Frame(main_area, bg=self.colors['bg_main'])
        header.pack(fill=X, padx=40, pady=25)
        Label(header, text="Password Details", font=self.font_title,
              bg=self.colors['bg_main'], fg=self.colors['text_dark']).pack(side=LEFT)
        self.info_label = Label(header, text=f"Total: {len(self.db.get('entries', []))} passwords",
                                font=self.font_small, bg=self.colors['bg_main'], fg=self.colors['text_gray'])
        self.info_label.pack(side=RIGHT)

        card_container = Frame(main_area, bg=self.colors['bg_main'])
        card_container.pack(fill=BOTH, expand=True, padx=40, pady=(0, 30))
        card = Frame(card_container, bg=self.colors['bg_white'], relief='solid', borderwidth=1,
                    highlightbackground=self.colors['border'], highlightthickness=1)
        card.pack(fill=BOTH, expand=True)
        form = Frame(card, bg=self.colors['bg_white'])
        form.pack(fill=BOTH, expand=True, padx=30, pady=25)

        # Site
        Label(form, text="Website or Service Name *", font=self.font_body, bg=self.colors['bg_white'], fg=self.colors['text_gray']).grid(row=0, column=0, sticky=W, pady=(0, 6))
        site_frame = Frame(form, bg=self.colors['bg_white'], highlightbackground=self.colors['border'], highlightthickness=1)
        site_frame.grid(row=1, column=0, sticky=EW, pady=(0, 12))
        Label(site_frame, text="🌐", bg=self.colors['bg_white'], font=self.font_body).pack(side=LEFT, padx=(15, 10))
        self.site_e = Entry(site_frame, font=self.font_body, bg=self.colors['bg_white'], fg=self.colors['text_dark'], insertbackground=self.colors['blue_primary'], relief='flat', borderwidth=0)
        self.site_e.pack(side=LEFT, fill=X, expand=True, ipady=12, padx=(0, 15))

        # Username 
        Label(form, text="Username or Email", font=self.font_body, bg=self.colors['bg_white'], fg=self.colors['text_gray']).grid(row=2, column=0, sticky=W, pady=(0, 6))
        user_frame = Frame(form, bg=self.colors['bg_white'], highlightbackground=self.colors['border'], highlightthickness=1)
        user_frame.grid(row=3, column=0, sticky=EW, pady=(0, 12))
        Label(user_frame, text="👤", bg=self.colors['bg_white'], font=self.font_body).pack(side=LEFT, padx=(15, 10))
        self.user_e = Entry(user_frame, font=self.font_body, bg=self.colors['bg_white'], fg=self.colors['text_dark'], insertbackground=self.colors['blue_primary'], relief='flat', borderwidth=0)
        self.user_e.pack(side=LEFT, fill=X, expand=True, ipady=12, padx=(0, 15))

        # Password 
        Label(form, text="Password *", font=self.font_body, bg=self.colors['bg_white'], fg=self.colors['text_gray']).grid(row=4, column=0, sticky=W, pady=(0, 6))
        pass_frame = Frame(form, bg=self.colors['bg_white'], highlightbackground=self.colors['border'], highlightthickness=1)
        pass_frame.grid(row=5, column=0, sticky=EW, pady=(0, 8))
        Label(pass_frame, text="🔐", bg=self.colors['bg_white'], font=self.font_body).pack(side=LEFT, padx=(15, 10))
        self.pass_e = Entry(pass_frame, font=self.font_body, bg=self.colors['bg_white'], fg=self.colors['text_dark'], insertbackground=self.colors['blue_primary'], relief='flat', borderwidth=0, show='•')
        self.pass_e.pack(side=LEFT, fill=X, expand=True, ipady=12, padx=(0, 10))
        self.show_pass_btn = Button(pass_frame, text="👁️", font=('Segoe UI', 11), 
                                    bg=self.colors['bg_white'], fg=self.colors['text_gray'], 
                                    relief='flat', borderwidth=0, cursor='hand2', 
                                    activebackground=self.colors['bg_white'],
                                    command=self.toggle_password_visibility)
        self.show_pass_btn.pack(side=RIGHT, padx=(0, 12), pady=2)

        btn_row = Frame(form, bg=self.colors['bg_white'])
        btn_row.grid(row=6, column=0, sticky=EW, pady=(0, 12))
        ttk.Button(btn_row, text="⚡ Generate Password", command=self.on_generate, 
                  style='Secondary.TButton').pack(side=LEFT, padx=(0, 12))
        ttk.Button(btn_row, text="📋 Copy", command=self.on_copy, 
                  style='Secondary.TButton').pack(side=LEFT)

        # Notes
        Label(form, text="Notes (optional)", font=self.font_body, bg=self.colors['bg_white'], fg=self.colors['text_gray']).grid(row=7, column=0, sticky=W, pady=(0, 6))
        notes_frame = Frame(form, bg=self.colors['bg_white'], highlightbackground=self.colors['border'], highlightthickness=1)
        notes_frame.grid(row=8, column=0, sticky=EW, pady=(0, 12))
        notes_scroll = Scrollbar(notes_frame, width=12)
        notes_scroll.pack(side=RIGHT, fill=Y)
        self.notes_t = Text(notes_frame, font=self.font_body, bg=self.colors['bg_white'], 
                           fg=self.colors['text_dark'], insertbackground=self.colors['blue_primary'], 
                           relief='flat', borderwidth=0, height=3, wrap=WORD,
                           yscrollcommand=notes_scroll.set)
        self.notes_t.pack(side=LEFT, fill=BOTH, expand=True, padx=15, pady=12)
        notes_scroll.config(command=self.notes_t.yview)

        action_row = Frame(form, bg=self.colors['bg_white'])
        action_row.grid(row=9, column=0, sticky=EW, pady=(8, 0))
        self.save_btn = ttk.Button(action_row, text="💾 Save Password", command=self.add_update_entry, 
              style='Primary.TButton')
        self.save_btn.pack(side=LEFT, padx=(0, 12))
        ttk.Button(action_row, text="🗑️ Delete", command=self.delete_entry, 
                  style='Danger.TButton').pack(side=LEFT, padx=(0, 12))
        ttk.Button(action_row, text="✨ Clear Form", command=self.new_entry, 
                  style='Secondary.TButton').pack(side=LEFT)
        
        form.grid_columnconfigure(0, weight=1)
        self.password_visible = False
        self.filtered_indices = []
        self.refresh_listbox()

    # Master password dialog
    def show_master_password_dialog(self):
        dialog = Toplevel(self.root)
        dialog.title("🔐 Password Manager")
        dialog.geometry("450x320")
        dialog.configure(bg='white')
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        # Keep dialog above other windows during auth
        try:
            dialog.attributes('-topmost', True)
        except Exception:
            pass
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (450 // 2)
        y = (dialog.winfo_screenheight() // 2) - (320 // 2)
        dialog.geometry(f'450x320+{x}+{y}')
        result = {'password': None}
        header = Frame(dialog, bg='#2563eb', height=100)
        header.pack(fill=X)
        header.pack_propagate(False)
        Label(header, text="🔐", font=('Segoe UI', 32), bg='#2563eb', fg='white').pack(pady=(40, 10))
        Label(header, text="Welcome Back", font=('Segoe UI', 16, 'bold'), bg='#2563eb', fg='white').pack()
        content = Frame(dialog, bg='white', padx=40, pady=30)
        content.pack(fill=BOTH, expand=True)
        Label(content, text="Enter your master password to unlock your vault", font=('Segoe UI', 10), bg='white', fg='#6b7280', wraplength=350).pack(pady=(0, 20))
        pass_frame = Frame(content, bg='white', highlightbackground='#e5e7eb', highlightthickness=1)
        pass_frame.pack(fill=X, pady=(0, 20))
        Label(pass_frame, text="🔑", bg='white', font=('Segoe UI', 11)).pack(side=LEFT, padx=(10, 8))
        pass_entry = Entry(pass_frame, font=('Segoe UI', 11), bg='white', fg='#1f2937', insertbackground='#2563eb', relief='flat', borderwidth=0, show='•')
        pass_entry.pack(side=LEFT, fill=X, expand=True, ipady=10, padx=(0, 10))
        # Force focus into password entry so user can start typing immediately
        pass_entry.focus_set()
        # Additional delayed focus to override OS focus stealing
        pass_entry.after(75, lambda: pass_entry.focus_force())
        # Inline show password
        show_var = BooleanVar()
        def toggle():
            pass_entry.config(show='' if show_var.get() else '•')
        Checkbutton(content, text="Show password", variable=show_var, command=toggle, bg='white', fg='#6b7280').pack(anchor=W)

        # Status label for feedback
        status_lbl = Label(content, text='', font=('Segoe UI', 9), bg='white', fg="#7aef44")
        status_lbl.pack(anchor=W, pady=(6, 0))

        # Validate on typing and auto-close on success
        def validate_password(event=None):
            pwd = pass_entry.get()
            if not pwd:
                status_lbl.config(text='')
                return
            try:
                load_vault(pwd)
                result['password'] = pwd
                dialog.destroy()
            except ValueError:
                status_lbl.config(text='Typing')

        # Bind key release and Enter to validate
        pass_entry.bind('<KeyRelease>', validate_password)
        pass_entry.bind('<Return>', validate_password)

        self.root.wait_window(dialog)
        return result['password']

    # Utility functions
    def toggle_password_visibility(self):
        self.password_visible = not self.password_visible
        if self.password_visible:
            self.pass_e.config(show='')
            self.show_pass_btn.config(text='🙈')
        else:
            self.pass_e.config(show='•')
            self.show_pass_btn.config(text='👁️')

    def refresh_listbox(self):
        query = ''
        try:
            query = self.search_var.get().lower()
        except Exception:
            query = ''
        self.listbox.delete(0, END)
        self.filtered_indices = []
        for idx, entry in enumerate(self.db.get('entries', [])):
            site = entry.get('site', '')
            username = entry.get('username', '')
            if (not query) or (query in site.lower()) or (query in username.lower()):
                self.listbox.insert(END, site)
                self.filtered_indices.append(idx)
        self.info_label.config(text=f"Total: {len(self.db.get('entries', []))} passwords")

    def filter_passwords(self):
        # Kept for backward compatibility
        self.refresh_listbox()

    def on_select(self, event):
        selection = self.listbox.curselection()
        if not selection:
            return
        index = selection[0]
        try:
            real_idx = self.filtered_indices[index]
        except Exception:
            real_idx = index
        entry = self.db['entries'][real_idx]
        self.site_e.delete(0, END)
        self.site_e.insert(0, entry['site'])
        self.user_e.delete(0, END)
        self.user_e.insert(0, entry['username'])
        self.pass_e.delete(0, END)
        self.pass_e.insert(0, entry['password'])
        self.notes_t.delete('1.0', END)
        self.notes_t.insert('1.0', entry.get('notes', ''))
        # Indicate edit mode
        try:
            self.save_btn.config(text="💾 Save Changes")
        except Exception:
            pass

    def new_entry(self):
        self.site_e.delete(0, END)
        self.user_e.delete(0, END)
        self.pass_e.delete(0, END)
        self.notes_t.delete('1.0', END)
        self.listbox.selection_clear(0, END)
        try:
            self.save_btn.config(text="💾 Save Password")
        except Exception:
            pass

    def on_double_click(self, event):
        # Select item under cursor and populate form, focus first field
        try:
            idx = self.listbox.nearest(event.y)
            if idx is not None and idx >= 0:
                self.listbox.selection_clear(0, END)
                self.listbox.selection_set(idx)
                self.listbox.activate(idx)
                self.on_select(None)
                self.site_e.focus_set()
        except Exception:
            pass

    def show_list_context_menu(self, event):
        # Right-click: select item under cursor, then show Edit/Delete menu
        try:
            idx = self.listbox.nearest(event.y)
            if idx is not None and idx >= 0:
                self.listbox.selection_clear(0, END)
                self.listbox.selection_set(idx)
                self.listbox.activate(idx)
        except Exception:
            pass
        try:
            self.list_menu.tk_popup(event.x_root, event.y_root)
        finally:
            try:
                self.list_menu.grab_release()
            except Exception:
                pass

    def context_edit_selected(self):
        # Load the selected item into the form and focus
        self.on_select(None)
        try:
            self.site_e.focus_set()
        except Exception:
            pass

    def context_delete_selected(self):
        # Delete currently selected item
        self.delete_entry()

    def add_update_entry(self):
        site = self.site_e.get().strip()
        username = self.user_e.get().strip()
        password = self.pass_e.get().strip()
        notes = self.notes_t.get('1.0', END).strip()
        if not site or not password:
            messagebox.showerror("Error", "Site and password are required fields!")
            return
        selection = self.listbox.curselection()
        if selection:
            sel_idx = selection[0]
            try:
                idx = self.filtered_indices[sel_idx]
            except Exception:
                idx = sel_idx
            self.db['entries'][idx] = {'site': site, 'username': username, 'password': password, 'notes': notes}
        else:
            self.db.setdefault('entries', []).append({'site': site, 'username': username, 'password': password, 'notes': notes})
        self.refresh_listbox()
        try:
            save_vault(self.db, self.master_password)
            messagebox.showinfo("Saved", "Password saved to vault.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save vault:\n{e}")

    def delete_entry(self):
        selection = self.listbox.curselection()
        if not selection:
            return
        sel_idx = selection[0]
        try:
            idx = self.filtered_indices[sel_idx]
        except Exception:
            idx = sel_idx
        confirm = messagebox.askyesno("Delete", f"Are you sure you want to delete '{self.db['entries'][idx]['site']}'?")
        if confirm:
            self.db['entries'].pop(idx)
            self.refresh_listbox()
            self.new_entry()
            try:
                save_vault(self.db, self.master_password)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save vault:\n{e}")

    def on_generate(self):
        pwd = generate_password()
        self.pass_e.delete(0, END)
        self.pass_e.insert(0, pwd)
        pyperclip.copy(pwd)
        messagebox.showinfo("Password Generated", "Password copied to clipboard!")

    def on_copy(self):
        pwd = self.pass_e.get()
        if pwd:
            pyperclip.copy(pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    def save_vault_ui(self):
        # Make sure the current form is persisted before saving the vault
        site = self.site_e.get().strip()
        username = self.user_e.get().strip()
        password = self.pass_e.get().strip()
        notes = self.notes_t.get('1.0', END).strip()

        selection = self.listbox.curselection()
        if selection and site and password:
            # Update the selected entry with current form values
            sel_idx = selection[0]
            try:
                idx = self.filtered_indices[sel_idx]
            except Exception:
                idx = sel_idx
            self.db['entries'][idx] = {
                'site': site,
                'username': username,
                'password': password,
                'notes': notes
            }
        elif site and password:
            # Append a new entry if form looks like a new item
            self.db.setdefault('entries', []).append({
                'site': site,
                'username': username,
                'password': password,
                'notes': notes
            })

        # Persist to disk
        try:
            save_vault(self.db, self.master_password)
            self.refresh_listbox()
            messagebox.showinfo("Saved", "Vault saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save vault:\n{e}")

    def change_master_password(self):
        # Step 1: Ask for current password
        current_pwd = simpledialog.askstring("Current Master Password", 
                                             "Enter current master password:", 
                                             show='*', parent=self.root)
        if not current_pwd:
            return
        
        # Step 2: Verify current password
        try:
            load_vault(current_pwd)
        except ValueError:
            messagebox.showerror("Error", "Incorrect current master password!")
            return

        # Step 3: Ask for new password
        new_pwd = simpledialog.askstring("New Master Password", 
                                         "Enter new master password:", 
                                         show='*', parent=self.root)
        if not new_pwd:
            return
        
        confirm_pwd = simpledialog.askstring("Confirm New Password", 
                                             "Re-enter new master password:", 
                                             show='*', parent=self.root)
        if new_pwd != confirm_pwd:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        # Step 4: Save vault with new password
        self.master_password = new_pwd
        self.save_vault_ui()
        messagebox.showinfo("Success", "Master password changed successfully!")


if __name__ == "__main__":
    root = Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

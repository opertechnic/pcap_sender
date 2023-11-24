import threading
from scapy.all import *
import time
import sys
import psutil
import os
import base64
import json
import tkinter as tk
from tkinter import ttk, filedialog
from PIL import Image, ImageDraw, ImageTk


#=================================================================================================
class InterfaceSelector(tk.Toplevel):
    def __init__(self, parent, interfaces, file_info):
        super().__init__(parent)
        self.parent = parent
        
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        window_width = self.winfo_reqwidth()
        window_height = self.winfo_reqheight()

        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        self.geometry("+{}+{}".format(x, y))

        self.title("PCAP(Sender)")
        style = ttk.Style()
        self.file_info = file_info

        file_name = self.file_info[0]
        packet_count_info = self.file_info[1]

        self.label_file_info = ttk.Label(self, text=file_name, font=('Arial', 10))
        self.label_file_info.grid(column=0, row=0, columnspan=3, pady=10, sticky="w")

        buttonopen = ttk.Button(self, text=f"...", width=5, command=self.get_pcap_filename_gui)
        buttonopen.grid(column=2, row=0, sticky="e")
        
        label_interface = ttk.Label(self, text="  ")
        label_interface.grid(column=3, row=0)

        style.configure('TLabel', font=('Arial', 11))

        label_interface = ttk.Label(self, text=" Iнтерфейс:")
        label_interface.grid(column=0, row=1, columnspan=2)

        self.combo_var = tk.StringVar()
        self.combo = ttk.Combobox(self, textvariable=self.combo_var, values=interfaces, state="readonly",font=('Arial', 10))
        self.combo.grid(column=2, row=1, columnspan=1)
        #self.combo.config(state="disabled")
        self.combo.current(0)
        self.combo.config(state="normal")

        style.configure('TButton', font=('Arial', 11))

        self.button = ttk.Button(self, text=f" Вiдправити (спочатку оберiть файл) ", command=self.on_select)
        self.button.grid(column=0, row=3, columnspan=3, pady=10)
        self.button.config(state="disabled")
        
        image_size = (18, 18)
        image = Image.new("RGBA", image_size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(image)
        draw.line((0, 0, image_size[0]-2, image_size[1]-2), fill="red", width=6)
        draw.line((0, image_size[1]-2, image_size[0]-2, 0), fill="red", width=6)      
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
         
        cancel_base64_image = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAQlBMVEX+BwflXl7qPT3ZAQH5GRnxKSnnTk7u7u4BAAD////HAADkbGztAADkd3flhYWQAACrAAAnGRlZAAC5ubmKiopVVVWuujnMAAAACXBIWXMAAAsTAAALEwEAmpwYAAAGsGlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNy4xLWMwMDAgNzkuZWRhMmIzZiwgMjAyMS8xMS8xNC0xMjozMDo0MiAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iIHhtbG5zOnBob3Rvc2hvcD0iaHR0cDovL25zLmFkb2JlLmNvbS9waG90b3Nob3AvMS4wLyIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIDIzLjEgKFdpbmRvd3MpIiB4bXA6Q3JlYXRlRGF0ZT0iMjAyMy0xMS0yMlQxODowMzoxOCswMjowMCIgeG1wOk1vZGlmeURhdGU9IjIwMjMtMTEtMjJUMjE6NDQ6MzErMDI6MDAiIHhtcDpNZXRhZGF0YURhdGU9IjIwMjMtMTEtMjJUMjE6NDQ6MzErMDI6MDAiIGRjOmZvcm1hdD0iaW1hZ2UvcG5nIiBwaG90b3Nob3A6Q29sb3JNb2RlPSIyIiBwaG90b3Nob3A6SUNDUHJvZmlsZT0iQWRvYmUgUkdCICgxOTk4KSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpjYmZjNGUyZi0yZGYyLTRhNGItOTcwOS1jODViZGVjOTE4ZTAiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6ZTUyMzkyMTgtYmVjNS1jNjQ5LWJlNmYtMWVmZDlkZmUwM2E3IiB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6ZTUyMzkyMTgtYmVjNS1jNjQ5LWJlNmYtMWVmZDlkZmUwM2E3Ij4gPHhtcE1NOkhpc3Rvcnk+IDxyZGY6U2VxPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0iY3JlYXRlZCIgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDplNTIzOTIxOC1iZWM1LWM2NDktYmU2Zi0xZWZkOWRmZTAzYTciIHN0RXZ0OndoZW49IjIwMjMtMTEtMjJUMTg6MDM6MTgrMDI6MDAiIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkFkb2JlIFBob3Rvc2hvcCAyMy4xIChXaW5kb3dzKSIvPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6ZmM3MDRlYjQtMjRhNy02ODQ4LWI1NjktNjNkYTc4YjU4ZTQxIiBzdEV2dDp3aGVuPSIyMDIzLTExLTIyVDIxOjQzOjQzKzAyOjAwIiBzdEV2dDpzb2Z0d2FyZUFnZW50PSJBZG9iZSBQaG90b3Nob3AgMjMuMSAoV2luZG93cykiIHN0RXZ0OmNoYW5nZWQ9Ii8iLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOmNiZmM0ZTJmLTJkZjItNGE0Yi05NzA5LWM4NWJkZWM5MThlMCIgc3RFdnQ6d2hlbj0iMjAyMy0xMS0yMlQyMTo0NDozMSswMjowMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIDIzLjEgKFdpbmRvd3MpIiBzdEV2dDpjaGFuZ2VkPSIvIi8+IDwvcmRmOlNlcT4gPC94bXBNTTpIaXN0b3J5PiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PszgeJoAAACdSURBVBiVTc8xloMwEATRmpYAYbN7/2M6MA8biR4H3mCDyuvHasS/ZKmkZGs7UrIgVRO4P351gzLnRLylbVQ0LlV6gRajD+A1EYvmo8N9BzSFYxHzAQDXFLjKnDoBbm03EpALFHg+AWJRtp0MoLfApdJHwhDorJHSeiWMtQL1ZZWpD2vLCHm4EXKs/LxlR6WFHIvAX2umvh/SHz2MPsCtTJInQxxLAAAAAElFTkSuQmCC"
        
        self.button_cancel = ttk.Button(self, text=f" ", width=5, command=self.on_cancel)
        photo = tk.PhotoImage(data=cancel_base64_image)
        self.button_cancel.config(image=photo, compound="center")
        self.button_cancel.photo = photo
        
        self.stop_sending = False
        
        lbl1 = ttk.Label(self, text=" ")
        lbl1.grid(column=0, row=3)
        
        self.progress_width = window_width*1.4
        self.canv = tk.Canvas(self, width=self.progress_width, height=25)
        self.progress_brd = self.canv.create_rectangle(0, 0, self.progress_width, 25, fill="gray")
        self.progress = self.canv.create_rectangle(1, 1, 1, 23, fill="green")
        self.progress_text = self.canv.create_text(150, 13, text="Зачекайте ...", font=('Arial', 10), fill="white")

        labelauthor = ttk.Label(self, text="   PCAP(Sender) by DomicUA", font=('Arial', 8))
        labelauthor.grid(column=1, row=4)
        flagua = tk.Canvas(self, width=window_width, height=20)
        flagua.grid(column=2, row=4, columnspan=1)
        yellow_rect = flagua.create_rectangle(0, 0, 20, 8, fill="blue")
        blue_rect = flagua.create_rectangle(0, 8, 20, 16, fill="yellow")
        labelua = ttk.Label(self, text="https://github.com/code_404 ", font=('Arial', 8))
        labelua.grid(column=2, row=4, sticky="e")

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.resizable(width=False, height=False)

    #=================================================================================================          
    def update_progress(self,value,pkt,cnt):
        self.canv.coords(self.progress, 0, 0, self.progress_width/100*value, 25)
        self.canv.itemconfig(self.progress_text, text=f"Вiдправлено: {value}% ({pkt} з {cnt})")
        self.canv.update_idletasks()
        
    #=================================================================================================        
    def send_packets(self):
        global pcap_file
        if pcap_file is None:
            sys.exit(1)       
        pkts = rdpcap(pcap_file)
        if not pkts:
            print("Помилка: У вибраному файлі pcapng не знайдено пакетів, або несумiсний формат даних.")
            sys.exit(1)
        clk = pkts[0].time
        cpkt = 0
        for p in pkts:
            #print(p.time)
            if self.stop_sending:
                print("Вiдправлення перервано.")
                break
            cpkt = cpkt+1
            percent_complete = round(cpkt / len(pkts) * 100, 1)
            self.update_progress(percent_complete,cpkt,len(pkts))
            print(f"{percent_complete}%")
            time.sleep(float(p.time) - float(clk))
            clk = p.time
            try:
                sendp(p, iface=self.combo_var.get())
            except Exception as e:
                print(f"Помилка відправки пакету: {e}")
        print("Вiдправлення закiнчено.")
        self.canv.grid_remove()
        self.button_cancel.grid_remove()
        self.button.grid(column=0, row=3, columnspan=3, pady=10)
        root.update()
        
    #=================================================================================================
    def on_select(self):
        print (f"Обрано файл pcap: '{pcap_file}'")
        print (f"Обраний iнтерфейс: '{self.combo_var.get()}'")
        self.button.grid_remove()
        self.canv.grid(column=1, row=3, columnspan=3, sticky="w")
        self.button_cancel.grid(column=2, row=3, pady=13, sticky="e")
        root.update()
        threading.Thread(target=self.send_packets).start()
        self.stop_sending = False
        
    #=================================================================================================
    def on_close(self):
        self.destroy()
        root.update()
        sys.exit(1)
    
    #=================================================================================================   
    def on_cancel(self):
        self.stop_sending = True
        root.update()
        
    #=================================================================================================
    def get_pcap_filename_gui(self):
        current_directory = get_last_folder()
        file_path = filedialog.askopenfilename(
            initialdir=current_directory,
            title="Select pcapng file",
            filetypes=[("PCAPNG files", "*.pcapng"), ("All files", "*.*")]
        )
        
        print(f"Спроба вiдкрити файл {file_path}")

        if not file_path:
            print("Вибiр файлу вiдмiнено.")
            return

        save_last_folder(file_path)
        pkts = rdpcap(file_path)
        print(f"Файл {file_path} вiдкрито для вiдправки пакетiв.")
        if not pkts:
            print("Помилка: У вибраному файлі pcapng не знайдено пакетів.")
            return
        
        self.file_info = [f"  Файл: {os.path.basename(file_path)}",f"{len(pkts)}"]
        self.update_file_info_label()
        global pcap_file
        pcap_file = file_path
        self.button.config(state="normal")
        
    #=================================================================================================
    def update_file_info_label(self):
        self.label_file_info.config(text=self.file_info[0])
        self.button.config(text=f" Вiдправити {self.file_info[1]} пакетiв ")
        
#=================================================================================================
def get_last_folder():
    config_file_path = os.path.join(os.path.expanduser('~'), '.pcaplay_config.json')
    if os.path.exists(config_file_path):
        try:
            with open(config_file_path, 'r') as config_file:
                config_data = json.load(config_file)
                return config_data.get('last_folder', os.getcwd())
        except json.JSONDecodeError as e:
            with open(config_file_path, 'r') as config_file:
                print(config_file.read())
            return os.getcwd()
    else:
        return os.getcwd()

#=================================================================================================
def save_last_folder(folder_path):
    config_data = {'last_folder': os.path.dirname(folder_path)}
    config_file_path = os.path.join(os.path.expanduser('~'), '.pcaplay_config.json')
    with open(config_file_path, 'w') as config_file:
        json.dump(config_data, config_file)

#=================================================================================================
def get_available_interfaces():
    interfaces = []
    for iface, details in psutil.net_if_stats().items():
        if details.isup:
            interfaces.append(iface)
    return interfaces

#=================================================================================================
def main():
    global root
    print ("==================================================================================================")
    print ("=            Ваш мережевий iнтерфейс повинен пiдтримувати 'Promiscous' режим                  =")
    print ("==================================================================================================")
    
    root = tk.Tk()
    root.resizable(width=False, height=False)
    root.attributes('-fullscreen', False)
    root.withdraw()  

    file_info = ["  Виберiть файл для вiдправлення.", "0"]
    interface_selector = InterfaceSelector(root, get_available_interfaces(), file_info)
    root.mainloop()

if __name__ == "__main__":
    main()

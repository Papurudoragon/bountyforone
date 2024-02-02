import tkinter as tk


# setup GUI design

def interface():
    window = tk.Tk()
    greeting = tk.Label(text="bountyforone!", width=20, height=20)
    # frame = tk.Frame()
    menu = tk.Label(text="Menu Options", foreground="white", background="black", width=20, height=20)
    entry = tk.Entry(fg="blue", bg="white", width=50)
    button_all = tk.Button(text="Run all flags", width=10, height=1, bg="blue", fg="white")

    # grab input for domain field
    domain = entry.get()

    # pack our labels
    greeting.pack() 
    # frame.pack()
    menu.pack()
    entry.pack()
    button_all.pack()
    
    return window


def main():
    window = interface()
    window.mainloop()  # --> event listener for input

if __name__=="__main__":
    main()
from scapy.all import sniff, TCP, UDP, IP, DNS, Raw  # type:ignore
import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
from collections import Counter
import matplotlib.pyplot as plt

# Global Variables
packet_counter = Counter()  # Variable for Counting the no. of packets of the specific protocol
pause_flag = threading.Event()  # Used for pausing the thread without stopping it completely
stop_flag = threading.Event()  # Used for stopping the sniffing completely
sniffing_active = False  # Indicates whether sniffing is currently active
current_protocol_filter = "All"  # Indicates that all type of packets are to be captured
captured_packets = []  # Store all captured packets' details
search_term = ""
display_options = {"IP": False, "Ports": False, "Protocol": False, "Size": False}


# Function to process each packet
def process_packet(packet):
    global packet_counter, captured_packets
    if pause_flag.is_set():
        return

    try:
        if IP in packet:
            ip_src = packet[IP].src  # Extracts the source IP
            ip_dst = packet[IP].dst  # Extracts the destination IP
            protocol = "Other"
            size = len(packet)  # Size of packets will be displayed in bytes

            # Determine the protocol
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif DNS in packet:
                protocol = "DNS"

            # Applying the protocol filter
            if current_protocol_filter != "All" and current_protocol_filter != protocol:
                return

            # Increment protocol counter
            packet_counter[protocol] += 1

            # Building result string
            result = f"\n=> Packet Captured:\n"
            if display_options["IP"]:
                result += f"    Source IP: {ip_src}\n    Destination IP: {ip_dst}\n"
            if display_options["Protocol"]:
                result += f"    Protocol: {protocol}\n"
            if display_options["Ports"] and (TCP in packet or UDP in packet):
                result += f"    Source Port: {packet.sport}\n    Destination Port: {packet.dport}\n"
            if display_options["Size"]:
                result += f"    Packet Size: {size} bytes\n"
            if DNS in packet:
                
                dns_query = packet[DNS].qd.qname.decode() if packet[DNS].qd else "Unknown"
                result += f"    DNS Query: {dns_query}\n"
                packet_counter[protocol] +=1

            # Save packet to storage
            captured_packets.append(result)

            # Apply search term
            if search_term and search_term.lower() not in result.lower():
                return

            update_output(result)
            update_summary()

    except Exception as e:
        update_output(f"[!] Error processing packet: {e}\n")

# Defining a function which is responsible for searching and highlighting occurences of user provided search term
def search_stored_packets():
    search_term = search_entry.get()  # Get the search term from the entry box
    output_text.tag_remove('highlight', '1.0', tk.END)  # Remove previous highlights

    if not search_term:  # If search term is empty, do nothing
        return

    start_pos = '1.0' # Defined a start position as 1 that is starting from the first character
    found_any = False # A variable defined default as false and would be re-initialised afterwards if the term is found

    while True:
        # Search for the term in the text widget
        start_pos = output_text.search(search_term, start_pos, stopindex=tk.END, nocase=True)
        if not start_pos:  # No more matches
            break

        found_any = True
        end_pos = f"{start_pos}+{len(search_term)}c"  # Calculate the end position
        output_text.tag_add('highlight', start_pos, end_pos)  # Add highlight tag
        start_pos = end_pos  # Move to the next possible match

    if found_any:
        # Configure the highlight tag with desired style
        output_text.tag_config('highlight', background='yellow', foreground='black')
    else:
        update_output(f"No results found for '{search_term}'\n")

# Function to update the output display
def update_output(message):
    output_text.configure(state='normal')
    output_text.insert(tk.END, message)
    output_text.configure(state='disabled')
    output_text.see(tk.END)


# Function to update the summary of captured packets
def update_summary():
    summary_text.set(f"TCP: {packet_counter['TCP']} | UDP: {packet_counter['UDP']} | DNS: {packet_counter['DNS']} | Other: {packet_counter['Other']}")

# Function to start the sniffer in a new thread
def start_sniffer():
    global sniffing_active
    sniffing_active = True  # A flag that indicates sniffing is in process
    pause_flag.clear()  # Remove pause state and start sniffing
    sniff_thread = threading.Thread(target=sniff, kwargs={
        'prn': process_packet,
        'store': False,
        'stop_filter': lambda x: not sniffing_active
    })
    sniff_thread.daemon = True  # Automatically stops the sniffing once the program exits
    sniff_thread.start()


# Function to stop the sniffing process
def stop_sniffer():
    global sniffing_active
    sniffing_active = False  # Indicate that sniffing has stopped
    pause_flag.set()  # Pause the packet processing


# Function to pause the sniffing process
def pause_sniffer():
    pause_flag.set()


# Function to resume the sniffing process without restarting it
def resume_sniffer():
    pause_flag.clear()


# Function to clear the output display
def clear_output():
    output_text.configure(state='normal')
    output_text.delete(1.0, tk.END)
    output_text.configure(state='disabled')
    packet_counter.clear()
    update_summary()


# Function to apply protocol filter
def apply_filter():
    global current_protocol_filter
    current_protocol_filter = protocol_filter.get()
    update_summary()  # Update summary after applying the filter

# Function to toggle display options (IP, Ports, Protocol, Size)
def toggle_display(option):
    display_options[option] = not display_options[option]
    update_summary()  # Refresh summary after toggling


# Function to generate a bar chart based on the packet data
def show_visualization():
    if sum(packet_counter.values()) == 0:
        update_output("No packets captured yet.\n")
        return

    fig, ax = plt.subplots()
    labels, counts = zip(*packet_counter.items())
    ax.bar(labels, counts)
    ax.set_title("Packet Summary")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Count")
    plt.show()


# Function to set the search term based on user input
def set_search_term():
    global search_term
    search_term = search_entry.get()  # Get the search term from the entry box
    update_summary()  # Update summary after setting a new search term


# Function to toggle between light and dark themes
def toggle_theme():
    if app["bg"] == "#2E2E2E":  # Dark theme is active
        # Switch to light theme
        app.configure(bg="#FFFFFF")
        control_frame.configure(bg="#FFFFFF")
        filter_frame.configure(bg="#FFFFFF")
        display_frame.configure(bg="#FFFFFF")
        summary_label.configure(bg="#FFFFFF", fg="black")
        animation_label.configure(bg="#FFFFFF", fg="black")
        output_text.configure(bg="#FFFFFF", fg="black")
        BUTTON_STYLE.update({'background': '#4CAF50', 'foreground': 'black', 'activebackground': '#45a049'})
        LABEL_STYLE.update({'background': '#FFFFFF', 'foreground': 'black'})
        TEXT_STYLE.update({'background': '#FFFFFF', 'foreground': 'black'})
        ENTRY_STYLE.update({'background': '#FFFFFF', 'foreground': 'black'})
    else:  # Light theme is active
        # Switch to dark theme
        app.configure(bg="#2E2E2E")
        control_frame.configure(bg="#2E2E2E")
        filter_frame.configure(bg="#2E2E2E")
        display_frame.configure(bg="#2E2E2E")
        summary_label.configure(bg="#2E2E2E", fg="white")
        animation_label.configure(bg="#2E2E2E", fg="white")
        output_text.configure(bg="#1C1C1C", fg="white")
        BUTTON_STYLE.update({'background': '#4CAF50', 'foreground': 'white', 'activebackground': '#45a049'})
        LABEL_STYLE.update({'background': '#2E2E2E', 'foreground': 'white'})
        TEXT_STYLE.update({'background': '#1C1C1C', 'foreground': 'white'})
        ENTRY_STYLE.update({'background': '#333333', 'foreground': 'white'})


# Initializing the GUI application
if __name__ == "__main__":
    app = tk.Tk()  # Creates a Tkinter root window
    app.title("Network Packet Sniffer")

    # Apply a dark theme by default
    app.configure(bg="#2E2E2E")  # Dark background
    summary_text = tk.StringVar()  # For dynamically updating summary text

    # Custom Styles
    BUTTON_STYLE = {'background': '#4CAF50', 'foreground': 'white', 'activebackground': '#45a049', 'relief': 'flat', 'font': ('Arial', 10, 'bold')}
    ENTRY_STYLE = {'background': '#333333', 'foreground': 'white', 'relief': 'flat', 'font': ('Arial', 10)}
    LABEL_STYLE = {'background': '#2E2E2E', 'foreground': 'white', 'font': ('Arial', 12)}
    TEXT_STYLE = {'background': '#1C1C1C', 'foreground': 'white', 'font': ('Arial', 10)}

    # Frame for Controls (Start, Pause, Resume, Stop, etc.)
    control_frame = tk.Frame(app, bg="#2E2E2E")
    control_frame.pack(pady=10)

    start_button = tk.Button(control_frame, text="Start", command=start_sniffer, **BUTTON_STYLE)
    start_button.pack(side=tk.LEFT, padx=5)

    pause_button = tk.Button(control_frame, text="Pause", command=pause_sniffer, **BUTTON_STYLE)
    pause_button.pack(side=tk.LEFT, padx=5)

    resume_button = tk.Button(control_frame, text="Resume", command=resume_sniffer, **BUTTON_STYLE)
    resume_button.pack(side=tk.LEFT, padx=5)

    stop_button = tk.Button(control_frame, text="Stop", command=stop_sniffer, **BUTTON_STYLE)
    stop_button.pack(side=tk.LEFT, padx=5)

    clear_button = tk.Button(control_frame, text="Clear Output", command=clear_output, **BUTTON_STYLE)
    clear_button.pack(side=tk.LEFT, padx=5)

    visualize_button = tk.Button(control_frame, text="Visualize", command=show_visualization, **BUTTON_STYLE)
    visualize_button.pack(side=tk.LEFT, padx=5)

    # Add theme toggle button
    toggle_button = tk.Button(control_frame, text="Change Theme", command=toggle_theme, **BUTTON_STYLE)
    toggle_button.pack(side=tk.LEFT, padx=5)

    # Frame for Filters (Protocol Filter, Search, etc.)
    filter_frame = tk.Frame(app, bg="#2E2E2E")
    filter_frame.pack(pady=5)

    tk.Label(filter_frame, text="Filter Protocol:", **LABEL_STYLE).pack(side=tk.LEFT)
    protocol_filter = ttk.Combobox(filter_frame, values=["All", "TCP", "UDP", "DNS"], state="readonly")
    protocol_filter.set("All")
    protocol_filter.pack(side=tk.LEFT, padx=5)
    filter_button = tk.Button(filter_frame, text="Apply", command=apply_filter, **BUTTON_STYLE)
    filter_button.pack(side=tk.LEFT, padx=5)

    tk.Label(filter_frame, text="Search:", **LABEL_STYLE).pack(side=tk.LEFT, padx=5)
    search_entry = tk.Entry(filter_frame, **ENTRY_STYLE)
    search_entry.pack(side=tk.LEFT, padx=5)
    search_button = tk.Button(filter_frame, text="Set", command=search_stored_packets, **BUTTON_STYLE)
    search_button.pack(side=tk.LEFT, padx=5)

    # Frame for Display Options (IP, Ports, Protocol, Size)
    display_frame = tk.Frame(app, bg="#2E2E2E")
    display_frame.pack(pady=5)

    ip_check = tk.BooleanVar(value=display_options["IP"])
    protocol_check = tk.BooleanVar(value=display_options["Protocol"])
    ports_check = tk.BooleanVar(value=display_options["Ports"])
    size_check = tk.BooleanVar(value=display_options["Size"])

    ip_checkbox = tk.Checkbutton(display_frame, text="IP", variable=ip_check, command=lambda: toggle_display("IP"), bg="#2E2E2E", fg="white", selectcolor="gray")
    ip_checkbox.pack(side=tk.LEFT, padx=5)
    protocol_checkbox = tk.Checkbutton(display_frame, text="Protocol", variable=protocol_check, command=lambda: toggle_display("Protocol"), bg="#2E2E2E", fg="white", selectcolor="gray")
    protocol_checkbox.pack(side=tk.LEFT, padx=5)
    ports_checkbox = tk.Checkbutton(display_frame, text="Ports", variable=ports_check, command=lambda: toggle_display("Ports"), bg="#2E2E2E", fg="white", selectcolor="gray")
    ports_checkbox.pack(side=tk.LEFT, padx=5)
    size_checkbox = tk.Checkbutton(display_frame, text="Size", variable=size_check, command=lambda: toggle_display("Size"), bg="#2E2E2E", fg="white", selectcolor="gray")
    size_checkbox.pack(side=tk.LEFT, padx=5)

    # Summary Text
    summary_label = tk.Label(app, textvariable=summary_text, **LABEL_STYLE)
    summary_label.pack(pady=5)
    update_summary()

    # Animation Label for ongoing packet capture
    animation_label = tk.Label(app, text=".............", **LABEL_STYLE)
    animation_label.pack(pady=5)

    # Output Text (for packet info)
    output_text = scrolledtext.ScrolledText(app, **TEXT_STYLE, height=15, width=80, state='disabled')
    output_text.pack(pady=10)

    app.mainloop()

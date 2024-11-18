import socket
import struct
import random
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os
import time

class Packet:
    def __init__(self, seq_num=0, header_len=0, msg_type=0, data_length=0, ack=0, data=b''):
        self.seq_num = seq_num
        self.header_len = header_len
        self.msg_type = msg_type
        self.data_length = data_length
        self.ack = ack
        self.data = data
        self.checksum = 0

    def pack(self):
        packet = struct.pack('!I B B B', self.seq_num, self.header_len, self.msg_type, self.ack)

        if self.header_len == 1:
            packet += struct.pack('!H', self.data_length)


        packet += self.data  # Додаємо дані

        self.checksum = self.calculate_checksum(packet)
        packet += struct.pack('!H', self.checksum)

        return packet

    @classmethod
    def unpack(cls, packet):
        seq_num, header_len, msg_type, ack = struct.unpack('!I B B B', packet[:7])
        data_length = 0
        data_start_index = 7

        if header_len == 1:
            data_length = struct.unpack('!H', packet[7:9])[0]
            data_start_index = 9

        data = packet[data_start_index:-2]
        checksum = struct.unpack('!H', packet[-2:])[0]

        new_packet = cls(seq_num, header_len, msg_type, data_length, ack, data)
        new_packet.checksum = checksum
        return new_packet

    def calculate_checksum(self, packet):
        crc = 0xFFFF
        polynomial = 0xA001
        for byte in packet:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ polynomial
                else:
                    crc >>= 1
        return crc & 0xFFFF

    def verify_checksum(self):
        packet_without_checksum = struct.pack('!I B B B', self.seq_num, self.header_len, self.msg_type, self.ack)
        if self.header_len == 1:
            packet_without_checksum += struct.pack('!H', self.data_length)
        packet_without_checksum += self.data
        calculated_checksum = self.calculate_checksum(packet_without_checksum)
        return calculated_checksum == self.checksum

    generated_seq_num = random.randint(0, 1000)




def three_way_handshake(sock, addr, is_server):
    if is_server:
        data, addr = sock.recvfrom(1024)
        packet = Packet.unpack(data)
        if packet.msg_type == 0:  # SYN
            print(f"Received SYN from {addr}")
            response = Packet(seq_num=packet.seq_num + 1, header_len=0, msg_type=4, ack=1).pack()  # SYN-ACK
            sock.sendto(response, addr)
            print("Sent SYN-ACK")
            data, addr = sock.recvfrom(1024)
            packet = Packet.unpack(data)
            if packet.msg_type == 3:
                print("Connection established (ACK received)")
    else:
        packet = Packet(seq_num=random.randint(0, 1000), header_len=0, msg_type=0).pack()  # SYN packet
        sock.sendto(packet, addr)
        print("Sent SYN, waiting for SYN-ACK")
        data, addr = sock.recvfrom(1024)
        packet = Packet.unpack(data)
        if packet.msg_type == 4:  # SYN-ACK
            print("Received SYN-ACK, sending ACK")
            response = Packet(seq_num=packet.seq_num + 1, header_len=0, msg_type=3, ack=1).pack()  # ACK
            sock.sendto(response, addr)
            print("Connection established (ACK sent)")


class ChatApp:
        def __init__(self, root, is_server, listen_port, target_ip, target_port):

            self.root = root
            self.is_server = is_server
            self.listen_port = listen_port
            self.target_ip = target_ip
            self.target_port = target_port
            self.sock = None
            self.file_path = None
            self.target_addr = (target_ip, target_port)
            self.sent_packets = {}
            self.windowsize =4

            self.start_p2p_communication(self.is_server, self.listen_port , self.target_ip, self.target_port)

            self.missed_keep_alive = 0
            self.keep_alive_interval = 5
            self.keep_alive_missed_limit = 3
            self.is_connected = True
            self.last_activity_time = time.time()

            self.fragment_size = tk.IntVar(value=512)

            self.file_Packets_received = []

            self.packets_received = {}

            self.file_received = False

            tk.Label(root, text="Fragment size (bytes):").grid(row=1, column=2, padx=10, pady=5, sticky="e")
            self.fragment_entry = tk.Entry(root, textvariable=self.fragment_size, width=10)
            self.fragment_entry.grid(row=1, column=3, padx=10, pady=5, sticky="w")

            self.message_entry = tk.Entry(root, width=50)
            self.message_entry.grid(row=0, column=0, padx=10, pady=10)

            self.send_text_button = tk.Button(root, text="Send Text", command=self.send_text)
            self.send_text_button.grid(row=0, column=1, padx=5, pady=10)

            self.file_button = tk.Button(root, text="Choose File", command=self.choose_file)
            self.file_button.grid(row=1, column=0, padx=10, pady=5)

            self.send_file_button = tk.Button(root, text="Send File", command=self.send_file)
            self.send_file_button.grid(row=1, column=1, padx=5, pady=5)

            self.chat_window = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=20)
            self.chat_window.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

            threading.Thread(target=self.keep_alive_monitor).start()

        def keep_alive_monitor(self):
            while self.is_connected:
                time_since_last_activity = time.time() - self.last_activity_time
                if time_since_last_activity > self.keep_alive_interval:
                    self.send_keep_alive()
                    self.last_activity_time = time.time()
                    self.missed_keep_alive += 1
                    if self.missed_keep_alive >= self.keep_alive_missed_limit:
                        self.is_connected = False
                        self.chat_window.insert(tk.END, "Connection lost. Terminating program...\n")
                        time.sleep(1.5)
                        self.terminate_program()
                        return

        def send_keep_alive(self, ask =0 ):
            print("send keep alive")
            keep_alive_packet = self.create_packet(5, seq_num=1, ask=ask)
            self.sock.sendto(keep_alive_packet.pack(), self.target_addr)

        def terminate_program(self):
            print("termonating")
            self.is_connected = False
            self.sock.close()
            self.root.destroy()
            exit(0)

        def choose_file(self):
            self.file_path = filedialog.askopenfilename()
            if self.file_path:
                messagebox.showinfo("File Selected", f"Selected file: {self.file_path}")

        def send_file(self):
            if not self.file_path:
                messagebox.showwarning("No File Selected", "Please choose a file before sending.")
                return

            try:
                fragment_size = self.fragment_size.get() if self.fragment_entry.get() else 512
                if fragment_size <= 0:
                    raise ValueError("Fragment size must be greater than 0")
            except ValueError as e:
                messagebox.showerror("Invalid Fragment Size", str(e))
                return

            file_size = os.path.getsize(self.file_path)
            num_fragments = (file_size + fragment_size - 1) // fragment_size
            file_name = os.path.basename(self.file_path)
            with open(self.file_path, 'rb') as f:
                for i in range(num_fragments):
                    fragment_data = f.read(fragment_size)
                    packet = Packet(
                        seq_num=Packet.generated_seq_num,
                        header_len=1,
                        msg_type=2,
                        data_length=len(fragment_data),
                        ack=0,
                        data=fragment_data
                    )
                    self.sent_packets[packet.seq_num] = packet
                    self.sock.sendto(packet.pack(), self.target_addr)
                    self.chat_window.insert(tk.END, f"Sent fragment {i + 1}/{num_fragments} of {file_name}\n")
                    self.last_activity_time =time.time()
                    Packet.generated_seq_num += 1

            end_packet = Packet(
                seq_num=Packet.generated_seq_num,
                header_len=1,
                msg_type=6,
                data_length=0,
                ack=0,
                data=b''
            )
            self.sock.sendto(end_packet.pack(), self.target_addr)
            self.chat_window.insert(tk.END, "File sent successfully.\n")
            self.file_path = None

        def start_p2p_communication(self, is_server, listen_port, target_ip, target_port):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('', listen_port))
            target_addr = (target_ip, target_port)

            three_way_handshake(self.sock, target_addr, is_server)

            threading.Thread(target=self.receive_messages, args=(self.sock,)).start()
            threading.Thread(target=self.selective_repeat()).start()

        def selective_repeat(self):
            while True:
                if len(self.sent_packets) < 4:
                    break

                for packet in self.sent_packets:
                    time.sleep(0.1)

        def send_text(self):
            message = self.message_entry.get()
            if (message):
                packet = Packet(
                    seq_num=Packet.generated_seq_num,
                    header_len=1,
                    msg_type=1,
                    data_length=len(message),
                    ack=0,
                    data=message.encode()
                )
                self.sent_packets[packet.seq_num] = packet
                self.sock.sendto(packet.pack(), self.target_addr)
                self.chat_window.insert(tk.END, f"Sent: {message}\n")
                self.message_entry.delete(0, tk.END)
                Packet.generated_seq_num += 1
            else:
                print("type something to send, you cannot send nothing")
            self.last_activity_time =time.time()

        def create_packet(self, msg_type, seq_num , ask):
            packet = Packet(
                seq_num=seq_num,
                msg_type=msg_type,
                header_len= 0,
                ack=ask,
                data=b''
            )
            return packet

        def receive_messages(self, sock):
            while True:
                data, addr = self.sock.recvfrom(560)
                packet = Packet.unpack(data)
                self.last_activity_time = time.time()
                if packet.verify_checksum():
                    if packet.msg_type == 1:
                        message = packet.data.decode()
                        self.chat_window.insert(tk.END, f"Received: {message}\n")
                        print(f"Packet received from {addr}:")
                        print(f"  Sequence Number: {packet.seq_num}")
                        print(f"  Header Length: {packet.header_len}")
                        print(f"  Message Type: {packet.msg_type}")
                        print(f"  Data Length: {packet.data_length}")
                        print(f"  ACK: {packet.ack}")
                        print(f"  Checksum: {packet.checksum}")
                        print(f"  Data: {packet.data.decode()}\n")

                    elif packet.msg_type == 2:
                        self.file_received = False
                        self.file_Packets_received.append(packet)
                        self.chat_window.insert(tk.END, f"Received file fragment, sequence number: {packet.seq_num}\n")

                    elif packet.msg_type == 6:
                        print("im here")
                        self.save_received_file()
                        self.file_Packets_received.clear()

                    if packet.msg_type == 3 and packet.ack == 1:
                        if packet.seq_num in self.sent_packets:
                            del self.sent_packets[packet.seq_num]
                            print(f"ACK received for packet {packet.seq_num}")

                    if packet.msg_type ==3 and packet.ack == 0:
                        packet_to_resent =self.sent_packets[packet.seq_num]
                        self.sock.sendto(packet_to_resent.pack(), self.target_addr)

                    if packet.msg_type != 3:
                        self.packets_received[packet.seq_num] = self.create_packet(3, packet.seq_num , 1)
                    if packet.msg_type ==5:
                        print("keep_alive_here")
                        if packet.ack ==0:
                            print("received ask 0 keep alive")
                            self.send_keep_alive(ask=1)

                        else:
                            print ("received ask 1 keep alive")
                            self.missed_keep_alive =0
                    self.last_activity_time = time.time()
                else:
                    self.packets_received[packet.seq_num] = self.create_packet(3, packet.seq_num, 0)
                    print("checksum not verifyed, errors in text")
                    self.last_activity_time = time.time()
                if len(self.packets_received) >= self.windowsize:
                    for seq_num, packet1 in list(self.packets_received.items()):
                        self.sock.sendto(packet1.pack(), self.target_addr)
                        self.last_activity_time = time.time()
                    self.packets_received.clear()
                    

        def save_received_file(self):
            ordered_fragments = sorted(self.file_Packets_received, key=lambda packet: packet.seq_num)

            file_data = b''.join(packet.data for packet in ordered_fragments)
            file_path = filedialog.asksaveasfilename(title="Save received file")
            if file_path:
                with open(file_path, 'wb') as f:
                    f.write(file_data)
                self.chat_window.insert(tk.END, f"File received and saved as: {file_path}\n")

if __name__ == "__main__":
    root = tk.Tk()
    is_server = input("Is this the server node? (yes/no): ").strip().lower() == 'yes'
    listen_port = int(input("Enter the listening port: "))
    target_ip = input("Enter the target IP address: ")
    #target_ip = "10.10.27.122"
    target_port = int(input("Enter the target port: "))

    app = ChatApp(root, is_server, listen_port, target_ip, target_port)
    root.mainloop()
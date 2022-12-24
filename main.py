#Librerías y módulos.
from tkinter import END, HORIZONTAL, VERTICAL, PhotoImage, StringVar, Tk, Toplevel, messagebox, ttk, Scrollbar
from gui.widgets import *
from PIL import Image, ImageTk
from algorithms.symmetric import *
from algorithms.hash import *
from algorithms.asymmetric import *

#Variables globales.
keyTest = None

#Vectores de prueba.
listTestVector = []

#Función principal.
def main():
    '''VENTANA PRINCIPAL'''
    #Se crea ventana principal.
    window = Tk()
    window.title('Criptografía') #Encabezado de la ventana.
    window.geometry('700x570+300+100') #Tamaño y posición.
    window.resizable(False, False) #Ventana de tamaño fijo.

    '''VARIABLES DEL PROGRAMA'''

    #Texto plano para ser cifrado.
    plaintext = StringVar() #Symmetric Encryption Algorithms
    key = StringVar() #Symmetric Encryption Algorithms

    plaintextHF = StringVar() #Hash functions

    plaintextAEA = StringVar() #Asymmetric Encryption Algorithms



    #Algoritmos de cifrado.
    algorithms = ('Symmetric Encryption Algorithms', 'Hash Algorithms (384 and 512 bits)', 'Asymmetric Encryption Algorithms')

    '''FRAME PARA ALGORITMOS DE CIFRADO'''

    #Frame para mostrar las opciones de encriptación.
    frame_crypto = FrameCrypto(window)

    #LabelFrame para mostrar los algoritmos a seleccionar.
    lf_select =LabelFrameCrypto(frame_crypto, 'Encryption Algorithm', 20, 20, 658, 130)

    #Label para seleccionar el algoritmo de encriptación.
    LabelCrypto(lf_select, 'Select the family of algorithms you want to compare', 10, 30)

    lf_option0 = LabelFrameCrypto(frame_crypto, algorithms[0], 20, 160, 658, 360) #Symmetric Encryption Algorithms
    lf_option1 = LabelFrameCrypto(frame_crypto, algorithms[1], 20, 160, 658, 360) #Hash Algorithms (384 y 512 bits)
    lf_option2 = LabelFrameCrypto(frame_crypto, algorithms[2], 20, 160, 658, 360) #Asymmetric Encryption Algorithms

    '''WIDGETS PARA Symmetric Encryption Algorithms'''

    #Label para ingresar texto en claro.
    LabelCrypto2(lf_option0, 'Enter the message', 10, 79, 30)

    #Entry para ingresar el texto en claro.
    seaPTEntry = EntryPlainText(lf_option0, plaintext, 400, 29)

    #Label para ingresar la llave.
    LabelCrypto2(lf_option0, 'Enter the key', 10, 60, 60)

    #Entry para ingresar la llave.
    seaKeyEntry = EntryPlainText(lf_option0, key, 400, 59)

    #Función para generar una llave válida.
    def add_key():
        global keyTest
        keyTest = generate_key()
        key.set(keyTest.hex())


    #Botón para generar llave.
    ButtonGenerateKey(lf_option0, 'Generate Key', add_key, 581, 92)

    #Función para añadir vectores de prueba.
    def add_vector():
        global keyTest, listTestVector
        if plaintext.get() == '' or key.get() == '':
            messagebox.showerror('Invalid Action', 'You must enter a test vector and a key')
        else:
            seaListbox.insert(END, '<--------------------------------------------------------Test Vector-------------------------------------------------------->')
            seaListbox.insert(END, 'Plaintext: ' + plaintext.get())
            seaListbox.insert(END, 'Key: ' + key.get())
            seaListbox.insert(END, '')
            listTestVector.append({'plaintext':plaintext.get(), 'key': keyTest})
            seaKeyEntry.delete(0, END)
            seaPTEntry.delete(0, END)

    #Botón para agregar vector de prueba.
    ButtonAddVector(lf_option0, add_vector, 325, 130)

    #Scrollbar para listbox.
    scrolly = ttk.Scrollbar(lf_option0, orient=VERTICAL)
    scrollx = ttk.Scrollbar(lf_option0, orient=HORIZONTAL)

    #Listbox para valores.
    seaListbox = ListboxCrypto(lf_option0, 8, 160, 88, 9)
    seaListbox.yscrollcommand = scrolly.set
    seaListbox.xscrollcommand = scrollx.set

    scrolly.config(command=seaListbox.yview)
    scrolly.place(in_=seaListbox, relx=1, relheight=1, bordermode="inside")
    scrollx.config(command=seaListbox.xview)
    scrollx.place(in_=seaListbox, rely=1, relwidth=1, relheight=0.1, bordermode="inside")


    '''WIDGETS PARA Hash Functions 384 y 512 bits'''
    
    #Label para ingresar texto en claro.
    LabelCrypto2(lf_option1, 'Enter the message', 10, 79, 30)

    #Entry para ingresar el texto en claro.
    hfEntry = EntryPlainText(lf_option1, plaintextHF, 400, 29)

    #Función para añadir vectores de prueba.
    def add_vector_hf():
        global listTestVector
        if plaintextHF.get() == '':
            messagebox.showerror('Invalid Action', 'You must enter a test vector')
        else:
            hfListbox.insert(END, '<--------------------------------------------------------Test Vector-------------------------------------------------------->')
            hfListbox.insert(END, 'Plaintext: ' + plaintextHF.get())
            listTestVector.append(plaintextHF.get())
            hfEntry.delete(0, END)
            hfEntry.delete(0, END)

    #Botón para agregar vector de prueba.
    ButtonAddVector(lf_option1, add_vector_hf, 325, 80)

    #Scrollbar para listbox.
    scrollyHF = ttk.Scrollbar(lf_option1, orient=VERTICAL)
    scrollxHF = ttk.Scrollbar(lf_option1, orient=HORIZONTAL)

    #Listbox para valores.
    hfListbox = ListboxCrypto(lf_option1, 8, 106, 88, 12)
    hfListbox.yscrollcommand = scrollyHF.set
    hfListbox.xscrollcommand = scrollxHF.set

    scrollyHF.config(command=hfListbox.yview)
    scrollyHF.place(in_=hfListbox, relx=1, relheight=1, bordermode="inside")
    scrollxHF.config(command=hfListbox.xview)
    scrollxHF.place(in_=hfListbox, rely=1, relwidth=1, relheight=0.1, bordermode="inside")

    '''WIDGETS PARA Asymmetric Encryption Algorithms'''

    #Label para ingresar texto en claro.
    LabelCrypto2(lf_option2, 'Enter the message', 10, 79, 30)

    #Entry para ingresar el texto en claro.
    aeaEntry = EntryPlainText(lf_option2, plaintextAEA, 400, 29)

    def keys_info():
        messagebox.showinfo('Keys Info', 'For this group of encryption algorithms (Asymmetric) the public and private keys are generated automatically. These keys are shown in the results table.')

    #Botón para mostrar información de las llaves.
    photoInfo = PhotoImage(file = './gui/images/info.png')
    photoImageInfo = photoInfo.subsample(3, 3)
    bcInfo = ButtonCrypto(lf_option2, "Keys Info", keys_info, photoImageInfo, 581, 92)
    bcInfo.config(font = ('arial', 9, 'bold'), width = 80)
    bcInfo.place(x=261, y=62)

    def add_vector_asa():
        global listTestVector
        if plaintextAEA.get() == '':
            messagebox.showerror('Invalid Action', 'You must enter a test vector')
        else:
            aeaListbox.insert(END, '<--------------------------------------------------------Test Vector-------------------------------------------------------->')
            aeaListbox.insert(END, 'Plaintext: ' + plaintextAEA.get())
            listTestVector.append(plaintextAEA.get())
            aeaEntry.delete(0, END)
            aeaEntry.delete(0, END)

    #Botón para agregar vector de prueba.
    ButtonAddVector(lf_option2, add_vector_asa, 325, 100)

    #Scrollbar para listbox.
    scrollyAEA = ttk.Scrollbar(lf_option2, orient=VERTICAL)
    scrollxAEA = ttk.Scrollbar(lf_option2, orient=HORIZONTAL)

    #Listbox para valores.
    aeaListbox = ListboxCrypto(lf_option2, 8, 125, 88, 11)
    aeaListbox.yscrollcommand = scrollyAEA.set
    aeaListbox.xscrollcommand = scrollxAEA.set

    scrollyAEA.config(command=aeaListbox.yview)
    scrollyAEA.place(in_=aeaListbox, relx=1, relheight=1, bordermode="inside")
    scrollxAEA.config(command=aeaListbox.xview)
    scrollxAEA.place(in_=aeaListbox, rely=1, relwidth=1, relheight=0.1, bordermode="inside")


    def option(event):

        global listTestVector

        if cbx_select.get() == algorithms[0]:
            lf_option0.place(x=20 ,y=160)
            lf_option1.place_forget()
            lf_option2.place_forget()
            listTestVector.clear()
            seaListbox.delete(0, END)

        if cbx_select.get() == algorithms[1]:
            lf_option0.place_forget()
            lf_option1.place(x=20 ,y=160)
            lf_option2.place_forget()
            listTestVector.clear()
            hfListbox.delete(0, END)

        if cbx_select.get() == algorithms[2]:
            lf_option0.place_forget()
            lf_option1.place_forget()
            lf_option2.place(x=20 ,y=160)


    #Combobox para seleccionar el algoritmo de cifrado.
    cbx_select = ttk.Combobox(lf_select)
    cbx_select.config(cursor='hand2', width=39, font=('verdana', 10), justify='center')
    cbx_select['values'] = algorithms
    cbx_select['state'] = 'readonly'
    cbx_select.place(relx=0.5, y=60, anchor='center')
    cbx_select.current(0)
    cbx_select.bind('<<ComboboxSelected>>', option)
    option(None)


    '''VENTANA EMERGENTE PARA RESULTADOS'''

    def encrypt():

        if cbx_select.get() == algorithms[0]:
            if seaListbox.size() == 0:
                messagebox.showerror('Invalid Action', 'You must enter at least one vector')
            else:
                resultsTL = Toplevel()
                resultsTL.geometry('900x550+150+50')
                resultsTL.resizable(False, False)
                resultsTL.config(relief='groove', bd=2, bg='gray90')

                lf_option0 = LabelFrameCrypto(resultsTL, algorithms[0], 10, 10, 875, 525) #Symmetric Encryption Algorithms
                LabelCrypto(lf_option0, 'Algorithms: Chacha20 : AES-EBC : AES-CBC', 14, 30)

                #Scrollbar para TreeView.
                scrolly2 = ttk.Scrollbar(lf_option0, orient=VERTICAL)
                scrollx2 = ttk.Scrollbar(lf_option0, orient=HORIZONTAL)

                #TreeView.
                resultsTable = ttk.Treeview(lf_option0)
                resultsTable.place(relx=0.01, rely=0.128, width=840, height=410)
                resultsTable.configure(yscrollcommand=scrolly2.set, xscrollcommand=scrollx2.set)
                resultsTable.configure(selectmode='extended')
                scrolly2.config(command=resultsTable.yview)
                scrollx2.config(command=resultsTable.xview)
                scrolly2.place(in_=resultsTable, relx=1, relheight=1, bordermode="inside")
                scrollx2.place(in_=resultsTable, rely=1, relwidth=1, bordermode="inside")
                resultsTable.configure(columns=(
                    'plaintext',
                    'key',
                    'encryption',
                    'timeencryption',
                    'resourcesencryption',
                    'decode',
                    'timedecode',
                    'resourcesdecode'
                ))

                resultsTable.column('#0', width=100)
                resultsTable.column('plaintext', width=500)
                resultsTable.column('key', width=700)
                resultsTable.column('encryption', width=700)
                resultsTable.column('timeencryption', width=300)
                resultsTable.column('resourcesencryption', width=500)
                resultsTable.column('decode', width=500)
                resultsTable.column('timedecode', width=300)
                resultsTable.column('resourcesdecode', width=500)

                resultsTable.heading('#0', text='Algorithm')
                resultsTable.heading('plaintext', text='Plaintext')
                resultsTable.heading('key', text='Key')
                resultsTable.heading('encryption', text='Encryption')
                resultsTable.heading('timeencryption', text='Time Encryption')
                resultsTable.heading('resourcesencryption', text='Resources Encryption')
                resultsTable.heading('decode', text='Decode')
                resultsTable.heading('timedecode', text='Time Decode')
                resultsTable.heading('resourcesdecode', text='Resources Decode')
                
                for vector in listTestVector:
                    results = chacha20(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['key'],
                        results['encryption'],
                        results['timeEncryption'],
                        results['resourcesEncryption'],
                        results['decode'],
                        results['timeDecode'],
                        results['resourcesDecode']
                    ))
                    results = aes_cbc(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['key'],
                        results['encryption'],
                        results['timeEncryption'],
                        results['resourcesEncryption'],
                        results['decode'],
                        results['timeDecode'],
                        results['resourcesDecode']
                    ))
                    results = aes_ebc(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['key'],
                        results['encryption'],
                        results['timeEncryption'],
                        results['resourcesEncryption'],
                        results['decode'],
                        results['timeDecode'],
                        results['resourcesDecode']
                    ))


        elif cbx_select.get() == algorithms[1]:
            if hfListbox.size() == 0:
                messagebox.showerror('Invalid Action', 'You must enter at least one vector')
            else:
                resultsTL = Toplevel()
                resultsTL.geometry('900x550+150+50')
                resultsTL.resizable(False, False)
                resultsTL.config(relief='groove', bd=2, bg='gray90')

                lf_option1 = LabelFrameCrypto(resultsTL, algorithms[1], 10, 10, 875, 525) #Symmetric Encryption Algorithms
                LabelCrypto(lf_option1, 'Algorithms: SHA-2 (384 and 512 bits) : SHA-3 (384 and 512 bits)', 14, 30)

                #Scrollbar para TreeView.
                scrolly2 = ttk.Scrollbar(lf_option1, orient=VERTICAL)
                scrollx2 = ttk.Scrollbar(lf_option1, orient=HORIZONTAL)

                #TreeView.
                resultsTable = ttk.Treeview(lf_option1)
                resultsTable.place(relx=0.01, rely=0.128, width=840, height=410)
                resultsTable.configure(yscrollcommand=scrolly2.set, xscrollcommand=scrollx2.set)
                resultsTable.configure(selectmode='extended')
                scrolly2.config(command=resultsTable.yview)
                scrollx2.config(command=resultsTable.xview)
                scrolly2.place(in_=resultsTable, relx=1, relheight=1, bordermode="inside")
                scrollx2.place(in_=resultsTable, rely=1, relwidth=1, bordermode="inside")
                resultsTable.configure(columns=(
                    'plaintext',
                    'encryption',
                    'timeencryption',
                    'resourcesencryption',
                ))

                resultsTable.column('#0', width=100)
                resultsTable.column('plaintext', width=500)
                resultsTable.column('encryption', width=700)
                resultsTable.column('timeencryption', width=300)
                resultsTable.column('resourcesencryption', width=500)

                resultsTable.heading('#0', text='Algorithm')
                resultsTable.heading('plaintext', text='Plaintext')
                resultsTable.heading('encryption', text='Encryption')
                resultsTable.heading('timeencryption', text='Time Encryption')
                resultsTable.heading('resourcesencryption', text='Resources Encryption')
                
                for vector in listTestVector:
                    results = sha2_384(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['encryption'],
                        results['timeEncryption'],
                        results['resourcesEncryption'],
                    ))
                    results = sha3_384(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['encryption'],
                        results['timeEncryption'],
                        results['resourcesEncryption'],
                    ))
                    results = sha2_512(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['encryption'],
                        results['timeEncryption'],
                        results['resourcesEncryption'],
                    ))
                    results = sha3_512(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['encryption'],
                        results['timeEncryption'],
                        results['resourcesEncryption'],
                    ))

        elif cbx_select.get() == algorithms[2]:
            if aeaListbox.size() == 0:
                messagebox.showerror('Invalid Action', 'You must enter at least one vector')
            else:
                resultsTL = Toplevel()
                resultsTL.geometry('900x550+150+50')
                resultsTL.resizable(False, False)
                resultsTL.config(relief='groove', bd=2, bg='gray90')

                lf_option2 = LabelFrameCrypto(resultsTL, algorithms[1], 10, 10, 875, 525) #Symmetric Encryption Algorithms
                LabelCrypto(lf_option2, 'Algorithms: RSA-OAEP : RSA-PSS : ECDSA-PRIME FIELD : ECDSA-BINARY FIELD', 14, 30)
                

                #Scrollbar para TreeView.
                scrolly2 = ttk.Scrollbar(lf_option2, orient=VERTICAL)
                scrollx2 = ttk.Scrollbar(lf_option2, orient=HORIZONTAL)

                #TreeView.
                resultsTable = ttk.Treeview(lf_option2)
                resultsTable.place(relx=0.01, rely=0.128, width=840, height=410)
                resultsTable.configure(yscrollcommand=scrolly2.set, xscrollcommand=scrollx2.set)
                resultsTable.configure(selectmode='extended')
                scrolly2.config(command=resultsTable.yview)
                scrollx2.config(command=resultsTable.xview)
                scrolly2.place(in_=resultsTable, relx=1, relheight=1, bordermode="inside")
                scrollx2.place(in_=resultsTable, rely=1, relwidth=1, bordermode="inside")
                resultsTable.configure(columns=(
                    'plaintext',
                    'privateKey',
                    'publicKey',
                    'signarute',
                    'timeSignature',
                    'resourcesSignature',
                    'verify',
                    'timeVerify',
                    'resourcesVerify'
                ))

                resultsTable.column('#0', width=100)
                resultsTable.column('plaintext', width=500)
                resultsTable.column('privateKey', width=500)
                resultsTable.column('publicKey', width=500)
                resultsTable.column('signarute', width=500)
                resultsTable.column('timeSignature', width=300)
                resultsTable.column('resourcesSignature', width=300)
                resultsTable.column('verify', width=500)
                resultsTable.column('timeVerify', width=300)
                resultsTable.column('resourcesVerify', width=300)

                resultsTable.heading('#0', text='Algorithm')
                resultsTable.heading('plaintext', text='Plaintext')
                resultsTable.heading('privateKey', text='Private Key')
                resultsTable.heading('publicKey', text='Public Key')
                resultsTable.heading('signarute', text='Signature')
                resultsTable.heading('timeSignature', text='Time Signature')
                resultsTable.heading('resourcesSignature', text='Resources Signature')
                resultsTable.heading('verify', text='Verify')
                resultsTable.heading('timeVerify', text='Time Verify')
                resultsTable.heading('resourcesVerify', text='Resources Verify')
                
                for vector in listTestVector:
                    results = rsa_oaep(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['privateKey'],
                        results['publicKey'],
                        results['signarute'],
                        results['timeSignature'],
                        results['resourcesSignature'],
                        results['verify'],
                        results['timeVerify'],
                        results['resourcesVerify']
                    ))

                    results = rsa_pss(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['privateKey'],
                        results['publicKey'],
                        results['signarute'],
                        results['timeSignature'],
                        results['resourcesSignature'],
                        results['verify'],
                        results['timeVerify'],
                        results['resourcesVerify']
                    ))

                    results = ecdsa(vector)
                    resultsTable.insert('', END, text=results['algorithm'], values=(
                        results['plaintext'],
                        results['privateKey'],
                        results['publicKey'],
                        results['signarute'],
                        results['timeSignature'],
                        results['resourcesSignature'],
                        results['verify'],
                        results['timeVerify'],
                        results['resourcesVerify']
                    ))

    #Botón de iniciar.
    photo2 = PhotoImage(file = './gui/images/key_start.png')
    photoimage2 = photo2.subsample(3, 3)
    ButtonCrypto(frame_crypto, 'Encrypt', encrypt, photoimage2, 285, 545)


    '''FRAME PARA DATOS DE LA ASIGNATURA'''

    #Se crea frame para mostrar datos del equipo.
    frame_sd = FrameCrypto(window)

    #Se crea frame para diseño.
    frame_d = FrameDesign(frame_sd)

    #Contenido del frame de datos del equipo.
    imagen = ImageTk.PhotoImage(Image.open('./gui/images/fi.png')) #Logo de la FI.
    LabelLogo(frame_d, imagen)

    #Datos de la institución y asignatura.
    LabelCrypto(frame_d, 'UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO', 14, 190)
    LabelCrypto(frame_d, 'FACULTAD DE INGENIERÍA', 14, 220)
    LabelCrypto(frame_d, 'CRIPTOGRAFÍA', 14, 250)
    LabelCrypto(frame_d, 'PROYECTO FINAL', 14, 280)

    #Datos de los integrantes.
    LabelCrypto(frame_d, 'INTEGRANTES', 14, 330)
    LabelCrypto(frame_d, 'ÁLVAREZ LORAN JUAN PABLO', 14, 370)
    LabelCrypto(frame_d, 'PALACIOS RODRÍGUEZ DIEGO OCTAVIO', 14, 405)
    LabelCrypto(frame_d, 'REYES GONZÁLEZ AGUSTÍN ÓSCAR', 14, 440)

    #Botón de iniciar.
    photo = PhotoImage(file = './gui/images/key_start.png')
    photoImage = photo.subsample(3, 3)
    ButtonCrypto(frame_sd, "Let's encrypt", frame_crypto.tkraise, photoImage, 285, 530)

    #Botón de home.
    photoHome = PhotoImage(file = './gui/images/home.png')
    photoImageHome = photoHome.subsample(3, 3)
    ButtonHome(frame_crypto, 'Home', frame_sd.tkraise, photoImageHome, 205, 545)

    #Función para salir de la aplicación.
    def exit():
        response = messagebox.askokcancel(message='Do you want to exit the application?')
        if response == True:
            window.destroy()

    #Botón de salir.
    photoExit = PhotoImage(file = './gui/images/exit.png')
    photoImageExit = photoExit.subsample(3, 3)
    ButtonHome(frame_crypto, 'Exit', exit, photoImageExit, 492, 545)

    window.mainloop() #Mantiene la ventana principal abierta.

#Se ejecuta la función principal.
if __name__ == '__main__':
    main()
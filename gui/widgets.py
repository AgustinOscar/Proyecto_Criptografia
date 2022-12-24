from tkinter import BOTTOM, END, FLAT, LEFT, TOP, Button, Entry, Frame, Label, LabelFrame, Listbox
from tkinter import ttk



'''BUTTONS'''

class ButtonAddVector(Button):
    def __init__(self, master, event, posx, posy):
        super().__init__(
            master,
            text = 'Add Test Vector',
            command = event,
            cursor = 'hand2',
            width = 76,
            relief = 'groove',
            bd = 1,
            bg='green2',
            fg = 'white',
            font = ('verdana', 10, ''),
            activeforeground = 'white',
            activebackground = 'green4',
        )
        self.place(x=posx, y=posy, anchor='center')
        self.cambiar_boton(self, 'green4', 'white')
    
    #Función para cambiar las propiedades de los botones.
    def cambiar_boton(self, boton, colorletra, colorLetra2):
        boton.bind('<Enter>', func = lambda e: boton.config(foreground=colorletra))
        boton.bind('<Leave>', func = lambda e: boton.config(foreground=colorLetra2))

class ButtonCrypto(Button):
    def __init__(self, master, text, event, image, posx, posy):
        super().__init__(
            master,
            text = text,
            command = event,
            cursor = 'hand2',
            width = 150,
            relief = 'groove',
            bd = 1,
            bg='steel blue',
            fg = 'white',
            font = ('verdana', 12, 'bold'),
            activeforeground = 'white',
            activebackground = 'gray50',
            image = image, 
            compound = LEFT
        )
        self.place(relx=0.5, y=posy, anchor='center')
        self.cambiar_boton(self, 'gray90', 'white')
    
    #Función para cambiar las propiedades de los botones.
    def cambiar_boton(self, boton, colorletra, colorLetra2):
        boton.bind('<Enter>', func = lambda e: boton.config(foreground=colorletra))
        boton.bind('<Leave>', func = lambda e: boton.config(foreground=colorLetra2))

class ButtonGenerateKey(Button):
    def __init__(self, master, text, event, posx, posy):
        super().__init__(
            master,
            text = text,
            command = event,
            cursor = 'hand2',
            width = 12,
            relief = 'raise',
            bd = 1,
            bg='gray50',
            fg = 'white',
            font = ('verdana', 10, ''),
            activeforeground = 'white',
            activebackground = 'gray40',
        )
        self.place(x=posx, y=posy, anchor='center')
        self.cambiar_boton(self, 'gray90', 'white')
    
    #Función para cambiar las propiedades de los botones.
    def cambiar_boton(self, boton, colorletra, colorLetra2):
        boton.bind('<Enter>', func = lambda e: boton.config(foreground=colorletra))
        boton.bind('<Leave>', func = lambda e: boton.config(foreground=colorLetra2))

class ButtonHome(Button):
    def __init__(self, master, text, event, image, posx, posy):
        super().__init__(
            master,
            text = text,
            command = event,
            cursor = 'hand2',
            width = 100,
            relief = 'groove',
            bd = 1,
            bg='steel blue',
            fg = 'white',
            font = ('verdana', 12, 'bold'),
            activeforeground = 'gray90',
            activebackground = 'gray50',
            image = image, 
            compound = LEFT
        )
        self.place(x=posx, y=posy, anchor='center')
        self.cambiar_boton(self, 'gray90', 'white')
    
    #Función para cambiar las propiedades de los botones.
    def cambiar_boton(self, boton, colorletra, colorLetra2):
        boton.bind('<Enter>', func = lambda e: boton.config(foreground=colorletra))
        boton.bind('<Leave>', func = lambda e: boton.config(foreground=colorLetra2))


'''ENTRYS'''

#Entry para clave en texto claro.
class EntryPlainText(Entry):
    def __init__(self, master, variable, posx, posy):
        super().__init__(
            master, 
            font = ('verdana', 10),
            justify = 'center',
            width = 60,
            textvariable = variable,
            background = 'gray85'
            )
        self.place(x=posx, y=posy, anchor='center')


'''FRAMES'''

#Frame para las opciones de selección de algoritmo critográfico.
class FrameCrypto(Frame):
    def __init__(self, master):
        super().__init__(
            master,
            width = 699,
            height = 569,
            relief = 'groove',
            bd = 1,
            bg='gray90',
            )
        self.place(x=0, y=0)

class FrameCrypto2(Frame):
    def __init__(self, master, posy, width, height):
        super().__init__(
            master,
            width = width,
            height = height,
            relief = 'flat',
            bd = 0,
            bg='gray90',
            )
        self.place(relx=0.5, y=posy, anchor='center')

#Frame para diseño.
class FrameDesign(Frame):
    def __init__(self, master):
        super().__init__(
            master,
            width = 657,
            height = 480,
            relief = 'groove',
            bd = 2,
            bg='gray90',
            )
        self.place(x=20, y=20)


'''LABELS'''

class LabelCrypto2(Label):
    def __init__(self, master, text, fontsize, posx, posy):
        super().__init__(
            master = master,
            text = text,
            font = ('STIX', fontsize, 'bold'),
            fg = 'black',
            bg = 'gray90'
        )
        self.place(x=posx, y=posy, anchor='center')

class LabelCrypto(Label):
    def __init__(self, master, text, fontsize, posy):
        super().__init__(
            master = master,
            text = text,
            font = ('STIX', fontsize, 'bold'),
            fg = 'black',
            bg = 'gray90'
        )
        self.place(relx=0.5, y=posy, anchor='center')

#Label para logo de Santander del menú principal.
class LabelLogo(Label):
    def __init__(self, padre, imagen):
        super().__init__(
                padre,
                image = imagen,
                relief = 'groove',
                bd = 0,
                bg = 'gray90'
            )
        self.place(relx=0.5, y=90, anchor='center')


'''LABELFRAME'''

#LabelFrame para mostrar las opciones del programa.
class LabelFrameCrypto(LabelFrame):
    def __init__(self, padre, text, posx, posy, width, height):
        super().__init__(
                padre,
                text = text,
                relief = 'groove',
                fg = 'steel blue',
                font = ('arial', 14, 'bold'),
                bd = 2,
                bg = 'gray90',
                width = width,
                height = height
            )
        self.place(x=posx, y=posy)


'''LISTBOX'''
class ListboxCrypto(Listbox):
    def __init__(self, master, posx, posy, width, height):
        super().__init__(
            master,
            width = width,
            height = height,
            font = ('arial', 10),
            relief = 'ridge',
            bd = 2
            )
        self.place(x=posx, y=posy)
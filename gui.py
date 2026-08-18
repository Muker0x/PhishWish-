import tkinter as tk
from analyzer import URLAnalyzer

class URLAnalyzerGUI:
    #building gui 
    def __init__(self,root):
        self.root = root
        self.root.geometry("500x700")
        self.root.columnconfigure(0, weight=1)

        self.firstlabel = tk.Label(root,
        text="Enter URL ",
        font=("Arial",30)
        )
        self.firstlabel.grid(row=0, column=0)
        
        self.urlentry = tk.Entry(
            self.root,
            font=("Arial",35)
            )
        self.urlentry.grid(row=1, column=0)
        self.notice_label = tk.Label(self.root,
        text="",
        justify="center",
        font=("Arial",20)
        )
        self.notice_label.grid(row=4, column=0)
        
        self.analyze_btn = tk.Button(
            self.root,
            text="Analyze",
            height=3,
            width=15,
            font=("Arial",15),
            command=self.run_analysis
            )
        self.analyze_btn.grid(row=2, column=0)
        self.root.bind("<Return>", lambda enter: self.run_analysis())

        self.text = tk.Text(
        self.root,
        font=("Arial",22),
        )
        self.text.grid(row=5, column=0)

        self.score_label = tk.Label(
        self.root,
        text="",
        font=("Arial",22)

        )
        self.score_label.grid(row=3, column=0)
        
   
    #Defining the Analyze button function 
    def run_analysis(self):
        url = self.urlentry.get()
        self.text.configure(state="normal")
        self.text.delete("1.0", tk.END)
        if not url: #making it ask for url if entry is empty 
            self.notice_label.configure(text="please enter url")     
            self.score_label.configure(text="")
            return
        if not url.startswith(("http://","https://")): #making it ask for valid url if invalid url
            self.notice_label.configure(text="Please enter valid URL \n that starts with http/https")
            self.score_label.configure(text="")
            self.urlentry.delete(0,tk.END)


            return
        analysis = URLAnalyzer(url)#running analysis 
        warnings,score,api_warnings,risk_level = analysis.analyze()
        #making it display the correct output depending on the warnings  
        if api_warnings and warnings:
            self.score_label.configure(text=f"Risk:{score}/100\n{risk_level}")
            self.text.insert(tk.END,"Threat detected !!! \n Google safe browsing results:\n\n")
            self.text.insert(tk.END,"\n".join(api_warnings),"\n")
            self.text.insert(tk.END,"\n\n")
            self.text.insert(tk.END,"Local indicator results:\n\n")
            self.text.insert(tk.END,"\n\n".join(warnings))
            self.text.configure(state="disabled")
            self.urlentry.delete(0,tk.END)
        if api_warnings:
            self.score_label.configure(text=f"Risk:{score}/100 \n {risk_level}")
            self.text.insert(tk.END,"Threat detected !!! \n Google safe browsing results:\n\n")
            self.text.insert(tk.END,"\n".join(api_warnings),"\n")
            self.text.configure(state="disabled")
            self.urlentry.delete(0,tk.END)
        if warnings:
            self.score_label.configure(text=f"Risk:{score}/100 \n {risk_level}")
            self.text.insert(tk.END,"\n".join(warnings))
            self.text.configure(state="disabled")
            self.urlentry.delete(0, tk.END)
            self.notice_label.configure(text="")

        
        if not warnings and not api_warnings:
            self.notice_label.configure(text="URL Seems harmless")
            self.urlentry.delete(0,tk.END)
            self.score_label.configure(text="")
        



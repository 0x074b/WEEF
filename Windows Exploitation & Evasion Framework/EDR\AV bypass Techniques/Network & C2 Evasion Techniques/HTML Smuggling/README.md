# Definition

*As the name suggests, HTML smuggling lets an attacker "smuggle" an encoded malicious script within a specially crafted HTML attachment or web page.* 
*When a target user opens the HTML in their web browser, the browser decodes the malicious script, which, in turn, assembles the payload on the host device.* 
*Thus, instead of having a malicious executable pass directly through a network, the attacker builds the malware locally behind a firewall.*

![image](https://github.com/0x074b/Defense-Evasion/assets/83349783/884628a5-67ac-46da-af08-94078b49f434)

# How HTML smuggling works

*HTML smuggling uses legitimate features of HTML5 and JavaScript, which are both supported by all modern browsers, to generate malicious files behind the firewall.*
*Specifically, HTML smuggling leverages the HTML5 "download" attribute for anchor tags,*
*as well as the creation and use of a JavaScript Blob to put together the payload downloaded into an affected device.*

*In HTML5, when a user clicks a link, the "download" attribute lets an HTML file automatically download a file referenced in the "href" tag.*
*For example, the code below instructs the browser to download “malicious.docx” from its location and save it into the device as "safe.docx"*:

![image](https://github.com/0x074b/Defense-Evasion/assets/83349783/c38f3e1a-9f6a-4583-a10b-e67c406932ed)

*The anchor tag and a file’s "download" attribute also have their equivalents in JavaScript code, as seen below*:

![image](https://github.com/0x074b/Defense-Evasion/assets/83349783/619a78d2-3ce4-4034-943e-5d792a12265b)

*The use of JavaScript Blobs adds to the "smuggling" aspect of the technique.*
*A JavaScript Blob stores the encoded data of a file, which is then decoded when passed to a JavaScript API that expects a URL.* 
*This means that instead of providing a link to an actual file that a user must manually click to download,*
*the said file can be automatically downloaded and constructed locally on the device using JavaScript codes like the ones below*:

![image](https://github.com/0x074b/Defense-Evasion/assets/83349783/ef0b57cd-654a-4a7d-a8e6-f4476e849126)

*Today’s attacks use HTML smuggling in two ways: the link to an HTML smuggling page is included within the email message, or the page itself is included as an attachment. 
The following section provides examples of actual threats we have recently seen using either of these methods.*

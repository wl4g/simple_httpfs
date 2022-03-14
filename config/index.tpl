 <!DOCTYPE html>
<html>
<head>
    <title>Microsoft-HTTPSERVER/2.0</title>
</head>
<body>
    <h2>Index of: {}</h2>
    <hr>
    <form ENCTYPE="multipart/form-data" method="post" onsubmit="javascript:return document.getElementById('file').value.length>0;">
        <a style='position:absolute;width:100px;height:30px;margin-top:-2px;background-color:blue;text-align:center;border-radius:30px;color:white;box-shadow:2px 2px 3px #ccacac;font-weight:600;cursor:pointer;line-height:30px;'>Choose file</a>
        <input id="file" name="file" type="file" style='position:relative;width:189px;height:30px;left:-88px;top:-6px;z-index:300;opacity:0;border-radius:47px;cursor:pointer;'/>
        <input type="submit" value="Upload" style='position:relative;top:-2px;width:100px;height:30px;z-index:300;border-radius:47px;cursor:pointer;background:green;color:white;border:0;box-shadow:2px 2px 3px #ccacac;transition-duration:0.3s;font-weight:600;'/>
    </form>
    <hr>
    <ul>
        {}
    </ul>
    <hr>
</body>
</html>
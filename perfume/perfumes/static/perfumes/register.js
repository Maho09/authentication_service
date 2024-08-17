document.addEventListener('DOMContentLoaded', function () {
    
    submit = document.getElementById("sum")
    submit.onclick = function(e){
        val = document.getElementById("paword").value
        if (Boolean(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%]).{8,16}$/.test(val)) === false){
            alert("Password must be between 8 and 16 characters long, contain at least one digit, one lower case and one upper case character and at least one special character")
            e.preventDefault()
        };
}
    
}
)

function show_password(){
        x = document.getElementById("paword")
        y = document.getElementById("paword1")
        if (x.type === "password"){
            x.type = "text"
            y.type = "text"
        }
        else{
            x.type = "password"
            y.type = "password"
        }
        return 0;
        
    }
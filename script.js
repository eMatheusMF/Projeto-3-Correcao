function abrirlogin()   {
    document.getElementById('modal').style.top = "0%";
}
function fecharlogin()   {
    document.getElementById('modal').style.top = "-100%";
}

function abrirlogin2()   {
    document.getElementById('segundo').style.top = "17.5%";
}
function fecharlogin2()   {
    document.getElementById('segundo').style.top = "-100%";
}


const api = {
    key: "b1acd38efcd959af9979088d310b48a2",
    base: "https://api.openweathermap.org/data/2.5/",
    lang: "pt_br",
    units: "metric",
}

const pesquisa = document.querySelector('.form-control');

const pesquisa_button = document.querySelector('.btn');

const cidade = document.querySelector('.cidade');

const date = document.querySelector('.date');

const weather_t = document.querySelector('.ceu');

const tempo_img = document.querySelector('.tempo-img');

const tempo_temp = document.querySelector('.tempo-temp');

const temp_number = document.querySelector('.tempo-temp div');

const temp_unit = document.querySelector('.tempo-temp span');

const max_min = document.querySelector('.max-min');

const humidade = document.querySelector('.humidade');

function javascript(){
    
    window.addEventListener('load', () => {

        navigator.geolocation.getCurrentPosition(setPosition, showError);

        function setPosition(position) {
            console.log(position)
            let lat = position.coords.latitude;
            let long = position.coords.longitude;
            Resultado(lat, long);
        }
        function showError(error) {
            alert(`erro: ${error.message}`);
        }
    })

    function Resultado(lat, long) {

        fetch(`${api.base}weather?lat=${lat}&lon=${long}&lang=${api.lang}&units=${api.units}&APPID=${api.key}`)
            .then(res => {
                if (!res.ok) {
                    throw new Error(`http ERROR`)
                }
                return res.json();
            })
            .catch(error => {
                alert(error.message)
            })
            .then(res => {
                displayResultado(res)
            });
    }

    pesquisa_button.addEventListener('click', function() {
        buscaResultado(pesquisa.value)
    })

    pesquisa.addEventListener('keypress', enter)
    function enter(event) {
        key = event.keyCode
        
        if (key === 13) {
            buscaResultado(pesquisa.value)
        }
    }

    function buscaResultado(cidade) {

        fetch(`${api.base}weather?q=${cidade}&lang=${api.lang}&units=${api.units}&APPID=${api.key}`)
            .then(res => {
                if (!res.ok) {
                    throw new Error(`http error: status ${res.status}`)
                }
                return res.json();
            })
            .catch(error => {
                alert(error.message)
            })
            .then(res => {
                displayResultado(res)
            });
    }

    function displayResultado(weather) {

        console.log(weather)

        cidade.innerText = `${weather.name}, ${weather.sys.country}`;

        let now = new Date();
        date.innerText = dataDeHoje(now);

        let iconName = weather.weather[0].icon;
        tempo_img.innerHTML = `<img src="./icons/${iconName}.png">`;

        let temperatura = `${Math.round(weather.main.temp)}`;
        temp_number.innerHTML = temperatura;
        temp_unit.innerHTML = `°c`;

        weather_tempo = weather.weather[0].description;

        weather_t.innerText = Letter(weather_tempo);

        max_min.innerText = `${Math.round(weather.main.temp_min)}°c / ${Math.round(weather.main.temp_max)}°c`;

        humidade.innerHTML = weather.main.humidity;
    }

    function dataDeHoje(d) {

        let dias = ["Domingo", "Segunda-feira", "Terça-feira", "Quarta-feira", "Quinta-feira", "Sexta-feira", "Sábado"];
        let meses = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julio", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"];

        let diaSemana = dias[d.getDay()];
        let dia = d.getDate();
        let mes = meses[d.getMonth()];
        let ano = d.getFullYear();

        return `${diaSemana}, ${dia} de ${mes} ${ano}`;
    }

    function Letter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
}

const email = document.getElementById("email");
const password = document.getElementById("password");
const form = document.querySelector("form");

const email2 = document.getElementById("email2");
const password2 = document.getElementById("password2");
const name2 = document.getElementById("nom");
const foto = document.getElementById("foto");

function cadastrarDados()   {
    dado1.textContent = name2.value;
    dado2.textContent = email2.value;
    dado3.textContent = password2.value;
    perfil2.document = foto.value
}

function abrirlogin3()   {
    document.getElementById('terceiro').style.top = "17.5%";
}
function fecharlogin3()   {
    document.getElementById('terceiro').style.top = "-100%";
}

function pegaToken(){

    const inputEmail = document.querySelector('input[type="text"]');
    const inputPassword = document.querySelector('input[type="password"]');

    fetch('https://reqres.in/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            email: inputEmail.value,
            password: inputPassword.value,
        })
    }).then((response) => {
        if (response.status == 200) {
            javascript();
            textForm2.textContent = "Login feito com sucesso!";
            document.getElementById("textForm2").style.color = "green";
            document.getElementById("textForm2").style.backgroundColor = '#c2dbbe';
        }else{
            textForm2.textContent = "Usuário incorreto!";
            document.getElementById("textForm2").style.color = "red";
            document.getElementById("textForm2").style.backgroundColor = '#dbbebe';
        }
        return response.json();
    }).then((data) => {
        console.log(data)
    })
}

function validatorEmail(email) {
    let emailPattern = /^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$/;
    return emailPattern.test(email);
}
    
function validatorPassword(password) {
    let passwordPattern = /^[a-zA-Z0-9!@#$%^&*]{4,16}$/;
    return passwordPattern.test(password);
}

form.addEventListener("submit", (e) => {
    
    e.preventDefault()

    if (validatorEmail(email.value) !== true) {
        textEmail.textContent = "O formato do email deve ser Exemplo: xxxxx@xxx.com";
    } else {
        textEmail.textContent = "";
    }
    
    if (validatorPassword(password.value) !== true) {
        textPassword.textContent = "A senha deve conter no mínimo 4 caracteres";
    } else {
        textPassword.textContent = "";
    }
      
    if (email.value == "" || password.value == "") {
        textForm.textContent = "Você precisa preencher todos os campos!";
    } else {
        textForm.textContent = "";
    }
    
    if ( validatorEmail(email.value) === true && validatorPassword(password.value) === true ) {
        textForm.textContent = "";
        textEmail.textContent = "";
        textPassword.textContent = "";
    } else {
        console.log("Requisição não atendida");
    }

    pegaToken();


});

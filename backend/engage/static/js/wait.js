function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
  }

// var times = 0;
// function CheckStatus(data) {
//     const xtoken = getCookie('csrftoken');

//     return new Promise((resolve, reject) => {
//         $.ajax({
//             url: '/api/auth/reload_data/',
            
//             headers: {
//                 "X-CSRFToken": xtoken,
//             },
//             type: "post",
//             data: {
//                 msisdn: data.msisdn,
//                 idnetwork: data.idnetwork
//             },
//             error: function (value) {
//                 reject(value);
//             },
//             success: function (value) {
//                 resolve(value);
//             },
//         });
//     });
// }

var times = 0;

function CheckDataSync(data) {
    const xtoken = getCookie('csrftoken');

    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/auth/check_data_sync/',
            
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                aocTransID: data.aocTransID,
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            
            },
        });
    });
}

function LoadData(data) {
    const xtoken = getCookie('csrftoken');

    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/auth/load_data/',
            
            headers: {
                "X-CSRFToken": xtoken,
            },
            type: "post",
            data: {
                aocTransID: data.aocTransID,
            },
            error: function (value) {
                reject(value);
            },
            success: function (value) {
                resolve(value);
            
            },
        });
    });
}

var tt=0;
function showloader(){
$("#wait-modal .msg").removeClass("d-none");       
        $(".please_wait").addClass("d-none");
         $(".waitText").addClass("d-none");
         $(".errico").addClass("d-none");
         $(".preload").removeClass("d-none");
         $("#subscribeRetry").addClass("d-none");
}
function hideloader(){
$("#wait-modal .msg").removeClass("d-none");          
        $(".please_wait").addClass("d-none");
         $(".waitText").removeClass("d-none");
         $(".errico").removeClass("d-none");
         $(".preload").addClass("d-none");
         $(".is_updated").addClass("d-none");
         $("#subscribeRetry").removeClass("d-none");
         
}
//var data={'aocTransID':''};
function keepUpdated() {
    times += 1;
    if (times>50){
        data={}
        const urlParams = new URLSearchParams(window.location.search);
        data.aocTransID = urlParams.get('aocTransID');
        LoadData(data).then(res => {
            $('.login-form').trigger("reset");

            if(res['status_code']==84) //406 ?
            response_msg.html('Failed to recharge. Please try again later.').show();
            else if(res['status_code']==75)
            response_msg.html('Your subscription is pending.').show();
            else if(res['status_code']==56)
            response_msg.html('Profile does not exist.').show();

            setTimeout(keepUpdated, 5000); // 1000 milliseconds = 1 second
            setTimeout(function(){
                window.location.href = '/' //'/clear'          
            },1000);
        }).catch(e => {
            console.log("e", e);
            if(e.status==484) //406 ?
            response_msg.html('Failed to recharge. Please try again later.').show();
            else if(e.status==475)
            response_msg.html('Your subscription is pending.').show();
            else if(e.status==456)
            response_msg.html('Profile does not exist.').show();
            else{
            response_msg.html('Something went wrong. Please try again later.').show();  //  Error code: '+e.status
           
        }
    });
        //response_msg.html("Your request is under process. Please check back later.").show();  //  <a href='/'>Refresh</a>
        //showloader();
        $("#subscribeRetry").removeClass("d-none");
        return;
    }
    
    data={}
    response_msg = $('.sub_status');
    const urlParams = new URLSearchParams(window.location.search);
    data.aocTransID = urlParams.get('aocTransID');
    CheckDataSync(data).then(res => {
        response_msg.html("Subscription Success !").show();
        postLoginOTPRobi(data.aocTransID).then(res => {
            $('.login-form').trigger("reset");
            setTimeout(keepUpdated, 5000); // 1000 milliseconds = 1 second
            setTimeout(function(){
                window.location.href = '/' //'/clear'          
            },1000);
        }).catch(e => {
            console.log("e", e);
            if(e.status==471) //406 ?
            response_msg.html('Exceed maximum allowed attempts! Please try again later.').show();
            else if(e.status==472)
            response_msg.html('Invalid Phone Number provided!').show();
            else if(e.status==480)
            response_msg.html('Your subscription has ended. Please renew your subscription <a href="/register">here</a>.').show();
            else{
            response_msg.html('Something went wrong. Please try again later.').show();  //  Error code: '+e.status
           
        }
        setTimeout(function(){
            window.location.href = '/' //'/clear'          
        },1000);
        });
      // window.location.href = '/' //'/clear'
    }).catch(e => {
        if(e.status==-1){
        response_msg.html("We are subscribing you to Engage. Please wait...").show();
        showloader();}
        
        else {
        if (times<5){
        response_msg.html("Your subscription is under process...").show();
        showloader();}
        else{//invisible
        response_msg.html("Subscription Failed. Please <a href=\"#\" id=\"Re-Reg\">try again</a>.").show(); //$('.frmregister3').submit();
        hideloader();
        $("#wait-modal").find(".error-bd").removeClass("d-none"); 
        $("#subSubscribe").html('Try Again');
        $("#subscribeRetry").on('click', firstClick);
        $("#Re-Reg").on('click', firstClick);

        function firstClick() {
            // document.getElementById('frmregister3').submit();
            secondForm();
        }
        return
        }}
        setTimeout(keepUpdated, 5000);
    });
}

// function keepUpdated() {
//     times += 1;
//     // console.log("times = "+times);
//     if (times>50){
//         // response_msg.html("<img class='loading-img' src='/static/img/loading1.gif' /><br>Your request is under process. Please check back later. <a href='/'>Refresh</a>").show();
//        /////// clearInterval(tt);
//         response_msg.html("Your request is under process. Please check back later.").show();  //  <a href='/'>Refresh</a>
//         showloader();
//         $("#subscribeRetry").removeClass("d-none");
//         return;}
//     // console.log("Updating using token "+xtoken);
//     data = {}
//     data.msisdn = 'TR6485029596'//aocTransID; //usermobile; // $(".user_mobile").text();
//     // console.log(usermobile);
//     // important must add header check here
//     data.idnetwork = '1';
//     response_msg = $('.sub_status');
//     CheckStatus(data).then(res => {
//         //setBtnLoading(btn, false);
//         //$(".login-otp-form").show(); //invisible
//         response_msg.html("Subscription Success !").show();
//         hideloader();
//         $("#wait-modal").find(".success-bd").removeClass("d-none");
//         window.location.href = '/' //'/clear'
//     }).catch(e => {
//         if(e.status==472){ //invisible
//         response_msg.html('The number you have provided is invalid!').show();
//         hideloader();
//         $("#wait-modal").find(".error-bd").removeClass("d-none"); }
//         else if(e.status==475){
//         response_msg.html("We are subscribing you to Engage. You will receive a message on your number to confirm. Please wait...").show();
//         showloader();}
//         else if(e.status==476){
//         response_msg.html("Unsubscription Request pending...").show();
//         showloader();}
//         else if(e.status==456){
//         if (times<5){
//         response_msg.html("Your subscription is under process...").show();
//         showloader();}
//         else{//invisible
//         response_msg.html("Subscription Failed. Please <a href=\"#\" id=\"Re-Reg\">try again</a>.").show(); //$('.frmregister3').submit();
//         hideloader();
//         $("#wait-modal").find(".error-bd").removeClass("d-none"); 
//         $("#subSubscribe").html('Try Again');
//         $("#subscribeRetry").on('click', firstClick);
//         $("#Re-Reg").on('click', firstClick);

//         function firstClick() {
//             // document.getElementById('frmregister3').submit();
//             secondForm();
//         }
//         return
//         }}
//         else if(e.status==480){//invisible
//         response_msg.html("Your subscription has ended. Please renew your subscription <a href='/register'>here</a>.").show();
//         hideloader();
//         $("#wait-modal").find(".error-bd").removeClass("d-none"); 
//         return
//         }
//         else if(e.status==0){
//         response_msg.html("Request interrupted. Refreshing page...").show();
//         showloader();}
//         else{
//         response_msg.html('Something went wrong. Please try again later.').show();  // + +e.status  //invisible
//         hideloader();
//         $("#wait-modal").find(".error-bd").removeClass("d-none"); 
//         return;}
//         //setBtnLoading(btn, false); 

// //         $("#wait-modal .preload").addClass("d-none");

// //    ////////////////////// tt = setInterval(() => {
         
// //         var statusW = $(".sub_status").html();
// //         if(statusW != "" && statusW == "Subscription Success !")
// //         {
// //             $("#wait-modal .msg").removeClass("d-none");  
// //             $("#wait-modal").find(".error-bd").addClass("d-none");  
// //             $("#wait-modal").find(".success-bd").removeClass("d-none");          
// //             $(".please_wait").addClass("d-none");
// //            //////////////////// clearInterval(t);
// //         } 
// //         else if(statusW != "" && statusW != "Subscription Success !")
// //         {
// //             $("#wait-modal .msg").removeClass("d-none");  
// //             $("#wait-modal").find(".error-bd").removeClass("d-none");  
// //             $("#wait-modal").find(".success-bd").addClass("d-none");          
// //             $(".please_wait").addClass("d-none");
// //             ////////////clearInterval(t);
// //         } 
         
//     /////////////////////}, 50);

//         setTimeout(keepUpdated, 5000);
//     });
//     //setTimeout(keepUpdated(), 5000);
   

    
//}
setTimeout(keepUpdated, 5000);
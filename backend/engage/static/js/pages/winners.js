var mobileOS = mobilecheck();
if(mobileOS=='pc')
   $('body').addClass('desktop');


   
$(function () {

    $('.sec-3-1 .drp_tournament').selectize({
      sortField: 'text'
    });
    $('.sec-3-1 .drp_game').selectize({
      sortField: 'text'
    });
    
  // load winners on page load
  getWinners($('.drp_game').val(),$('.drp_tournament  .selectize-input').find('.item').attr('data-value'));
  $('.drp_game').on('change', function() {
    var value = $(this).val();
    if($('.drp_tournament .selectize-dropdown-content').find('.option').length==0){
      
      setTimeout(() => {
      $('.drp_tournament  .selectize-input').click();
      $('.drp_tournament  .selectize-dropdown').addClass('invisible');
      }, 500);
      
    }
     setTimeout(function(){
      $('.drp_tournament  .selectize-dropdown-content').find('.option').hide();
      var selected=false;
      $('.selectize-dropdown').removeClass('invisible');
      $('.hiddenTournament_select option').each(function(ind){
        var firstItem = $('.hiddenTournament_select option').eq(ind);
        if($('.drp_tournament  .selectize-dropdown-content').find('.option').length > 0){
          $('.drp_tournament  .selectize-dropdown-content').find('.option').each(function(ind1){
            if(value =='' || (value == firstItem.attr('game') &&  $('.drp_tournament  .selectize-dropdown-content').find('.option').eq(ind1).attr('data-value')==firstItem.attr('value'))){
              
              $('.drp_tournament  .selectize-dropdown-content').find('.option').eq(ind1).show();
              if(!selected)
              {
                $('.drp_tournament  .selectize-input').find('.item').attr('data-value', $('.drp_tournament  .selectize-dropdown-content').find('.option').eq(ind1).attr('data-value'));
                $('.drp_tournament  .selectize-input').find('.item').text($('.drp_tournament  .selectize-dropdown-content').find('.option').eq(ind1).text());
                selected=true;
              }
            }
          })
        }
      
        
      })
   
      getWinners($('.drp_game').val(), $('.drp_tournament  .selectize-input').find('.item').attr('data-value'));
      $('.sec-3-1 select.drp_tournament option').eq(0).attr("value",$('.drp_tournament  .selectize-input').find('.item').attr('data-value'));
      $('.sec-3-1 select.drp_tournament option').eq(0).text($('.drp_tournament .selectize-input').find('.item').text());
      $('.drp_tournament  .selectize-dropdown-content').find('.option').removeClass('selected').removeClass('active');
      $('.drp_tournament  .selectize-dropdown-content').find('.option[data-value='+$('.drp_tournament  .selectize-input').find('.item').attr('data-value')+']').addClass('selected').addClass('active');
    
      var valueTournament = $('.drp_tournament  .selectize-input').find('.item').attr('data-value');
      if(valueTournament == undefined)
            $(".loading-tr").find(".loading-img").hide();
     },500);
      
    
   
  });
  $('.sec-3-1 .drp_tournament').on('change', function() {
      setTimeout(function(){
        $('.drp_tournament  .selectize-input').find('.item').text($('.drp_tournament  .selectize-dropdown-content').find('.option.active').text());
        $('.drp_tournament  .selectize-input').find('.item').attr('data-value',$('.drp_tournament  .selectize-dropdown-content').find('.option.active').attr('data-value'));
        getWinners($('.drp_game').val(),$('.drp_tournament  .selectize-input').find('.item').attr('data-value'));


       var valueTournament = $('.drp_tournament  .selectize-input').find('.item').attr('data-value');
       if(valueTournament == undefined)
          $(".loading-tr").find(".loading-img").hide();
      },600)
    
    })
     $('.drp_tournament  .selectize-control').click(function(){
         var active = $('.drp_tournament.selectized').val();
          setTimeout(function(){
                 if(active==$('.drp_tournament  .selectize-dropdown-content').find('.option.active.selected').attr('data-value') || $('.drp_tournament  .selectize-dropdown-content').find('.option.active.selected').length==0)
                 return;
                 if($('.drp_tournament.selectized').val() != $('.drp_tournament  .selectize-dropdown-content').find('.option.active').attr('data-value')){
                  $('.drp_tournament  .selectize-input').find('.item').text($('.selectize-dropdown-content').find('.option.active').text());
                  $('.drp_tournament  .selectize-input').find('.item').attr('data-value',$('.drp_tournament  .selectize-dropdown-content').find('.option.active').attr('data-value'));
                  getWinners($('.drp_game').val(),$('.drp_tournament .selectize-input').find('.item').attr('data-value'));
                 }
               
          },700)
     });


  
  // add scroll for winners list
    $('.scroll_wrapper').css('width',($('.package').outerWidth(true) + 20)*$('.package').length + 'px');
  //
  

  //scroll to tournaments section or games section when user clicks the navbar links
  $("#hometournaments, #homegames,#li_winners").on("click", function () { //,#a-redeem,#a-prize
    hashchanged();
  });
});

function matchCustom(params, data) {
  // If there are no search terms, return all of the data
  if ($.trim(params.term) === '') {
    return data;
  }

  // Do not display the item if there is no 'text' property
  if (typeof data.text === 'undefined') {
    return null;
  }

  // `params.term` should be the term that is used for searching
  // `data.text` is the text that is displayed for the data object
  if (data.text.indexOf(params.term) > -1) {
    var modifiedData = $.extend({}, data, true);
    modifiedData.text += ' (matched)';

    // You can return modified objects from here
    // This includes matching the `children` how you want in nested data sets
    return modifiedData;
  }

  // Return `null` if the term should not be displayed
  return null;
}
$(".featured-item a").on("click", function(e) {
  if(!is_authenticated) {
    return
  }
  const featured_game_id = $(this).data('id');

  $.ajax({
      url: `${featured_game_retrieve}${featured_game_id}/`,
      headers: {},
      type: "get",
      success: function (data) {
        if(data.coins > 0){
          $('#user-coins').css('background','#EA2D2D');
        }
        const user_coins = parseInt($("#actual-user-coins").text()) + data.coins;
        $("#actual-user-coins, .user-coins").html(user_coins);
      },
  });
})

//handle upgrade subscription click
$("#upgrade-package-pgame-modal .modal-content").on("click", function () {
  setBtnLoading($(this), true);

  function upgrade_subsp() {
      return new Promise((resolve, reject) => {
          $.ajax({
              url: upgrade_subscription.replace("user_uid", user_uid),
              headers: {
                  "X-CSRFToken": xtoken,
              },
              type: "post",
              data: {},
              error: function (value) {
                resolve(value);
              },
              success: function (value) {
                  value.is_sub
                  resolve(value);
                  if (value.is_sub == 'false')
                  {
                    window.location.href="/secured"
                  }
                  else{
                    $("#upgrade-package-pgame-modal").modal("hide");
                    setBtnLoading($("#upgrade-package-pgame-modal"), false);
                    window.location.reload(true);
                  }
                  
              },
          });
      });
  }

  upgrade_subsp().then(function (_) {
      
      // $("#upgrade-package-pgame-modal").modal("hide");
      // setBtnLoading($("#upgrade-package-pgame-modal"), false);
      //window.location.reload(true);
  }).catch(function (error) {
    $("#upgrade-package-pgame-modal").modal("hide");
      setBtnLoading($("#upgrade-package-pgame-modal"), false);
      showInfoModal('Error!', '<p>Something went wrong, please try again later.</p>')
  });
});

var tInt = setInterval(function(){

  if($('.st-btn[data-network="sms"]').length > 0){
    clearInterval(tInt);
    if(!(/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent))){
      // true for not mobile device
     $('.st-btn[data-network="sms"]').attr("style", "display:none!important");
    }else{
      // false for  mobile device
      $('.st-btn[data-network="sms"]').attr("style", "display:inline-block!important");
    }
  }

},50);
 




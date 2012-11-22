$(function() {
    $( "#btNew" ).button({
        icons: {
            primary: "ui-icon-circle-plus"
        }
    });
    $( "#btEnd" ).button({
        icons: {
            primary: "ui-icon-closethick"
        }
    });

    $( "#btStartStop" ).button({
        icons: {
            primary: "ui-icon-play"
        }
    })
    .click(function() {
        var options;
        if ( $( this ).text() === "start" ) {
            options = {
                label: "stop",
                icons: {
                    primary: "ui-icon-pause"
                }
            };
        } else {
            options = {
                label: "start",
                icons: {
                    primary: "ui-icon-play"
                }
            };
        }
        $( this ).button( "option", options );
    });

    $( "#btMore" ).button({
        icons: {
            primary: "ui-icon-arrowrefresh-1-s"
        }
    });

    $( "#btEndAll" ).button({
        icons: {
            primary: "ui-icon-trash"
        }
    });

});


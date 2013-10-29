/* Mostly taken from https://wiki.gnome.org/WebKitGtk/
ProgrammingGuide/Tutorial*/
#include<stdio.h>
#include<stdlib.h>
#include <gtk/gtk.h>
#include <webkit/webkit.h>

#define MAX_URI_SIZE 2000

static void destroyWindowCb(GtkWidget* widget, GtkWidget* window);
static gboolean closeWebViewCb(WebKitWebView* webView, GtkWidget* window);
static gboolean loadErrorCb(WebKitWebView  *web_view, WebKitWebFrame *web_frame,
                       	      gchar *uri, gpointer web_error, gpointer user_data);


int main(int argc, char* argv[])
{
    char *hostname;
    int port;
    char *cafilename;
    char uri[MAX_URI_SIZE];

    if (argc!=4) {
        fprintf(stderr, "Usage: %s hostname port cafilename\n", argv[0]);
        exit(1);
    }
    hostname = argv[1];
    port = atoi(argv[2]);
    cafilename = argv[3];
    snprintf(uri, MAX_URI_SIZE, "https://%s:%d/", hostname, port);
    // Initialize GTK+
    gtk_init(&argc, &argv);

    // Create an 800x600 window that will contain the browser instance
    GtkWidget *main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(main_window), 800, 600);

    // Create a browser instance
    WebKitWebView *webView = WEBKIT_WEB_VIEW(webkit_web_view_new());

    // Create a scrollable area, and put the browser instance into it
    GtkWidget *scrolledWindow = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolledWindow),
            GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scrolledWindow), GTK_WIDGET(webView));

    // Set up callbacks so that if either the main window or the browser instance is
    // closed, the program will exit
    g_signal_connect(main_window, "destroy", G_CALLBACK(destroyWindowCb), NULL);
    g_signal_connect(webView, "close-web-view", G_CALLBACK(closeWebViewCb), main_window);
    g_signal_connect(webView, "load-error", G_CALLBACK(loadErrorCb), NULL);

    // Put the scrollable area into the main window
    gtk_container_add(GTK_CONTAINER(main_window), scrolledWindow);

    // Set the truested ca
    SoupSession *session = webkit_get_default_session ();
    g_object_set (session,
                  SOUP_SESSION_SSL_CA_FILE, cafilename,
                  NULL);

    // Load a web page into the browser instance
    webkit_web_view_load_uri(webView, uri);
    // Make sure that when the browser area becomes visible, it will get mouse
    // and keyboard events
    gtk_widget_grab_focus(GTK_WIDGET(webView));

    // Make sure the main window and all its contents are visible
    gtk_widget_show_all(main_window);
	
    // Run the main GTK+ event loop
    gtk_main();

    return 0;
}


static void destroyWindowCb(GtkWidget* widget, GtkWidget* window)
{
    gtk_main_quit();
}

static gboolean closeWebViewCb(WebKitWebView* webView, GtkWidget* window)
{
    gtk_widget_destroy(window);
    return TRUE;
}

static gboolean loadErrorCb(WebKitWebView  *web_view, WebKitWebFrame *web_frame,
                       	      gchar *uri, gpointer web_error, gpointer user_data)

{
    int ret = 0;
    int error_code = ((GError *)web_error)->code;

    if (error_code==7)/*load failed due to no http data*/ {
        fprintf(stdout, "0\n");
    }
    else if (error_code==2)/*load failed due to network connection*/ {
        ret = 1;
    }	
    else {
        fprintf(stdout,"%d\n", error_code);
    }
    
     gtk_main_quit();
     exit(ret);
     /* keeps the compiler happy*/
     return TRUE;
}

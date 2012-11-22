{-# LANGUAGE TypeFamilies, QuasiQuotes, MultiParamTypeClasses, TemplateHaskell, OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts, GADTs #-}
{-# LANGUAGE FlexibleInstances #-}

module RouteHandlers where
{-
 - This file defines the route handlers used by the server to perform
 - actions and return content when a request is received
 -}

import Yesod   hiding (Route(..))
import Foundation
import CapManCommunication (makeRequest, makeRequests)

writeLog :: String -> IO ()
writeLog s = putStrLn $ "LOG: " ++ s

--Handler for server root
getRootR :: Handler RepHtml
getRootR = do
    liftIO $ writeLog "getRoot handler called"
    defaultLayout [whamlet|<p>Server root.|]

--Handler returns a list of all available capturers
getCapturesR :: Handler RepHtml
getCapturesR = do
    liftIO $ writeLog "getCaptures handler called"
    defaultLayout [whamlet|^{requestListCaptures}|]

--Handler stops all capturers
deleteCapturesR :: Handler RepHtml
deleteCapturesR = do
    liftIO $ writeLog "deleteCaptures handler called"
    defaultLayout [whamlet|^{requestEndCaptures}|]

--Handler starts a new capturer with the given parameters. Returns the new capturers id
postNewCaptureR :: String -> Handler RepHtml
postNewCaptureR params = do
    liftIO $ writeLog "postNewCapture handler called"
    defaultLayout [whamlet|^{requestNewCapture params}|]

--Handler gets the json packets contained in the specified capturers buffer
getCaptureR :: Int -> Handler RepHtml
getCaptureR id = do
    liftIO $ writeLog "getCapture handler called"
    defaultLayout [whamlet|^{requestPacketsCapture id}|]

--Handler stops the specified capturer
deleteCaptureR :: Int -> Handler RepHtml
deleteCaptureR id = do
    liftIO $ writeLog "deleteCapture handler called"
    defaultLayout [whamlet|^{requestEndCaptures}|]


--Make a request to the connection manager and return the response
widgetFromRequest :: String -> Widget
widgetFromRequest request = do
    response <- liftIO $ makeRequest request
    [whamlet|#{response}|]

--Request and return a list of captures
requestListCaptures :: Widget
requestListCaptures = widgetFromRequest "getcaptures"

--Request and return the contents of a capture
requestPacketsCapture :: Int -> Widget
requestPacketsCapture id = widgetFromRequest $ "getcapture " ++ show id

--Request creation of a new capture, return capture id
requestNewCapture :: String -> Widget
requestNewCapture params = widgetFromRequest $ "newcapture " ++ show params

--Request the ending of a specified capture and return the response
requestEndCapture :: Int -> Widget
requestEndCapture id = widgetFromRequest $ "endcapture " ++ show id

--Request the ending of all captures, return the response
requestEndCaptures :: Widget
requestEndCaptures = widgetFromRequest "endcaptures"

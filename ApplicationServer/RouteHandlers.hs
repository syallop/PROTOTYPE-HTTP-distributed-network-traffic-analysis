{-# LANGUAGE TypeFamilies, QuasiQuotes, MultiParamTypeClasses, TemplateHaskell, OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts, GADTs #-}
{-# LANGUAGE FlexibleInstances #-}

module RouteHandlers where
{-
 - This file defines the route handlers. A handler is responsible for constructing a response to a client.
 - The 'routes' file maps URL's to the handlers defined in this file.
 -}

import Yesod   hiding (Route(..))
import Foundation
import CapManCommunication (makeRequest, makeRequests)

--Function for debugging purposes
writeLog :: String -> IO ()
writeLog s = putStrLn $ "LOG: " ++ s

--Handler for server root
getRootR :: Handler RepHtml
getRootR = do
    liftIO $ writeLog "getRoot handler called"
    defaultLayout [whamlet|<p>Server root.|]

--Returns a list of all available capturers
getCapturesR :: Handler RepHtml
getCapturesR = do
    liftIO $ writeLog "getCaptures handler called"
    rep <- liftIO $ repFromRequest "getcaptures"
    sendResponse rep

--Stops all capturers. Returns success status.
deleteCapturesR :: Handler RepHtml
deleteCapturesR = do
    liftIO $ writeLog "deleteCaptures handler called"
    rep <- liftIO $ repFromRequest "endcaptures"
    sendResponse rep

--Starts a new capturer with the given parameters. Returns the new capturers id
postNewCaptureR :: String -> Handler RepHtml
postNewCaptureR params = do
    liftIO $ writeLog "postNewCapture handler called"
    rep <- liftIO $ repFromRequest $ "newcapture " ++ params
    sendResponse rep

--Gets the json packets contained in the specified capturers buffer
getCaptureR :: Int -> Handler RepJson
getCaptureR id = do
    liftIO $ writeLog "getCapture handler called"
    rep <- liftIO $ repFromRequest $ "getcapture " ++ show id
    sendResponse rep

--Stops the specified capturer
deleteCaptureR :: Int -> Handler RepHtml
deleteCaptureR id = do
    liftIO $ writeLog "deleteCapture handler called"
    rep <- liftIO $ repFromRequest $ "endcapture " ++ show id
    sendResponse rep

--Returns the capture types the capture component understands
getSupportedTypesR :: Handler RepHtml
getSupportedTypesR = do
    liftIO $ writeLog "getSupportedTypes handler called"
    rep <- liftIO $ repFromRequest "getcapturertypes"
    sendResponse rep




--Make a request, return the response as a RepPlain
repFromRequest :: String -> IO RepPlain
repFromRequest request = do
    response <- makeRequest request
    return $ RepPlain $ toContent response

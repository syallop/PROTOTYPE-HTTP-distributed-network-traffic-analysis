{-# LANGUAGE TypeFamilies, QuasiQuotes, MultiParamTypeClasses, TemplateHaskell, OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts, GADTs #-}
{-# LANGUAGE FlexibleInstances #-}


{-
 - This file defines the entry point to the server application
 -}
import Yesod
import Yesod.Static

import Foundation     --Import the underlying site datastructures
import RouteHandlers  --Import the sites route handlers

--Tie together the site
mkYesodDispatch "APISite" resourcesAPISite

--Get some sample Json packets for the purpose of testing
getTestPackets :: Handler RepJson
getTestPackets = sendFile typeJson "./client/test/packets.json"

--Entry point
main = do
    client@(Static settings) <- static "client"
    warpDebug 3000 $ APISite client

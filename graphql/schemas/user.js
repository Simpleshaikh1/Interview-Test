const express = require('express')
const bodyParser = require('body-parser')
const {graphqlHTTP} = require('express-graphql')
const {buildSchema, GraphQLSchema, GraphQLObjectType } = require('graphql')
const mongoose = require('mongoose')

const Event = require('./models/event')
const User = require('./models/user')
const bcrypt = require('bcryptjs')
const app = express()

app.use(bodyParser.json())

const schema = new GraphQLSchema({
    query: new GraphQLObjectType({

        schema: buildSchema(`
    
            type User {
                _id:ID!,
                username:String!
                email:String!
                password:String
            }
    
            input UserInput {
                username:Stirng!
                email:String!
                password:String!
            }
    
            type RootQuery {
                users: [Users!]!
            }
    
            type RootMutation{
                createUser(userInput: UserInput): User
            }
    
            schema {
                query: RootQuery
                mutation:RootMutation
            }
        `),
    })
})


   

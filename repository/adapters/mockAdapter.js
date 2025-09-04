'use strict';

const { generateError } = require('../../utils/errors.js');
const generateMockData = require('../../utils/mockData.js');

// Keep mock data in-memory for the lifetime of the process (and across module reloads)
// This ensures inserts/updates are visible to subsequent queries while the server is alive.
const getMockStore = () => {
    if (!global.__JISME_MOCK_STORE__) {
        const mockData = generateMockData();
        global.__JISME_MOCK_STORE__ = {
            users: [...mockData.users],
            accounts: [...mockData.accounts],
            activities: [...mockData.activities]
        };
    }
    return global.__JISME_MOCK_STORE__;
};

const mockStore = getMockStore();

// Helper to generate MongoDB-like Object IDs
const generateObjectId = () => {
    const timestamp = Math.floor(new Date().getTime() / 1000).toString(16);
    const randomPart = Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0');
    const randomPart2 = Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0');
    
    return timestamp + randomPart + randomPart2;
};

// Helper to perform filtering on mock data
const filterDocuments = (collection, filter) => {
    if (!filter) return collection;
    
    return collection.filter(item => {
        for (const key in filter) {
            // Handle ObjectId for _id
            if (key === '_id' && filter[key] !== item[key]) {
                return false;
            }
            // Handle normal string equality
            else if (item[key] !== filter[key]) {
                return false;
            }
        }
        return true;
    });
};

const sendQuery = async function (collectionName, {
    action,
    filter,
    projection,
    limit,
    skip,
    sort,
    document,
    documents,
    update,
    pipeline
}) {
    console.log(`MOCK DB: ${action} on ${collectionName}`);
    
    // Determine which collection to use
    let collection = [];
    if (collectionName.includes('user') && !collectionName.includes('activity')) {
        collection = mockStore.users;
    } else if (collectionName.includes('account')) {
        collection = mockStore.accounts;
    } else if (collectionName.includes('activity')) {
        collection = mockStore.activities;
    } else {
        console.log(`Warning: Using empty collection for ${collectionName}`);
    }

    // Handle different action types
    if (action === 'count') {
        const filtered = filterDocuments(collection, filter);
        return filtered.length;
    }

    if (action === 'findOne') {
        const filtered = filterDocuments(collection, filter);
        return {
            data: {
                document: filtered.length > 0 ? { ...filtered[0] } : null
            }
        };
    }

    if (action === 'find') {
        let filtered = filterDocuments(collection, filter);
        
        // Apply skip if provided
        if (skip) {
            filtered = filtered.slice(skip);
        }
        
        // Apply limit if provided
        if (limit) {
            filtered = filtered.slice(0, limit);
        }
        
        // Apply sort if provided
        if (sort) {
            const sortField = Object.keys(sort)[0];
            const sortDirection = sort[sortField];
            
            filtered.sort((a, b) => {
                if (a[sortField] < b[sortField]) return sortDirection * -1;
                if (a[sortField] > b[sortField]) return sortDirection;
                return 0;
            });
        }
        
        return {
            data: {
                documents: filtered.map(doc => ({ ...doc }))
            }
        };
    }

    if (action === 'insertOne' && document) {
        const newDocument = { ...document };
        
        // Generate a new ID if not provided
        if (!newDocument._id) {
            newDocument._id = generateObjectId();
        }
        
        collection.push(newDocument);
        
        return {
            data: {
                insertedId: newDocument._id
            }
        };
    }

    if (action === 'insertMany' && documents) {
        const insertedIds = {};
        
        documents.forEach((doc, index) => {
            const newDocument = { ...doc };
            
            // Generate a new ID if not provided
            if (!newDocument._id) {
                newDocument._id = generateObjectId();
            }
            
            collection.push(newDocument);
            insertedIds[index] = newDocument._id;
        });
        
        return { insertedIds };
    }

    if (action === 'updateOne') {
        const filtered = filterDocuments(collection, filter);
        
        if (filtered.length === 0) {
            return { matchedCount: 0 };
        }
        
        // Find the index of the item to update
        const indexToUpdate = collection.findIndex(item => {
            for (const key in filter) {
                if (item[key] !== filter[key]) {
                    return false;
                }
            }
            return true;
        });
        
        if (indexToUpdate !== -1) {
            // Apply update to the document
            for (const key in update) {
                collection[indexToUpdate][key] = update[key];
            }
            
            return { matchedCount: 1 };
        }
        
        return { matchedCount: 0 };
    }

    if (action === 'deleteOne') {
        const initialLength = collection.length;
        
        // Find the index of the item to delete
        const indexToDelete = collection.findIndex(item => {
            for (const key in filter) {
                if (item[key] !== filter[key]) {
                    return false;
                }
            }
            return true;
        });
        
        if (indexToDelete !== -1) {
            collection.splice(indexToDelete, 1);
            return { deletedCount: 1 };
        }
        
        return { deletedCount: 0 };
    }

    if (action === 'aggregate') {
        // Basic implementation for count aggregation
        if (pipeline && pipeline.length === 2 && 
            pipeline[0].$match && pipeline[1].$count === 'count') {
            
            const filtered = filterDocuments(collection, pipeline[0].$match);
            return {
                data: {
                    documents: [{ count: filtered.length }]
                }
            };
        }
        
        throw generateError('Mock DB error', 'Aggregate pipeline not supported in mock mode', 500);
    }

    throw generateError('Mock DB error', `Action '${action}' not implemented in mock mode`, 500);
};

exports.sendQuery = sendQuery; 

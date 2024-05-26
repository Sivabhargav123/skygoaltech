const express = require('express');
const authRouter = require('./auth');
const bodyParser = require('body-parser');

const app = express();

app.use(bodyParser.json());

app.use('/api', authRouter);

app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
